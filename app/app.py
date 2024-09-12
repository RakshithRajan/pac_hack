from web3.datastructures import AttributeDict
import spacy
import streamlit as st
import os
import base64
import re
import json
import logging
import random
import string
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from io import StringIO
import sys
import hashlib
from web3 import Web3
import json



logging.basicConfig(
    filename="data_protection_tool.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

blockchain_url = (
    "http://127.0.0.1:7545"  # Ensure this matches your Ganache or node setup
)
web3 = Web3(Web3.HTTPProvider(blockchain_url))

contract_address = "0xfeEf63649c2925bc4C664076bd3eCF959f50A310"  # Replace with your deployed contract address

# Use the user's suggested approach
compiled_contract_path = os.path.join(
    os.path.dirname(__file__), "../build/contracts/AuditLog.json"
)
with open(compiled_contract_path, "r") as file:
    audit_contract_json = json.load(file)
    audit_contract_abi = audit_contract_json["abi"]


contract = web3.eth.contract(address=contract_address, abi=audit_contract_abi)

# Set default account
web3.eth.default_account = web3.eth.accounts[0]


def get_audit_logs():
    """
    Retrieve all audit logs from the blockchain.
    """
    try:
        logs = contract.functions.getLogs().call()
        for log in logs:
            print(
                f"User: {log[0]}, Hash: {log[1]}, Action: {log[2]}, Timestamp: {log[3]}"
            )
    except Exception as e:
        print(f"Error retrieving logs: {e}")


def serialize_web3_object(obj):
    if isinstance(obj, AttributeDict):
        return {k: serialize_web3_object(v) for k, v in obj.items()}
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    if isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    return str(obj)

def add_audit_log(data_hash: str, action: str, timestamp: str):
    try:
        tx_hash = contract.functions.addLog(data_hash, action, timestamp).transact()
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        print(f"Log added to blockchain. Transaction Hash: {tx_hash.hex()}")
        print("Transaction Receipt:")
        print(json.dumps(serialize_web3_object(receipt), indent=2))

        st.success(f"Log added to blockchain. Transaction Hash: {tx_hash.hex()}")

        # Fetch events using get_logs instead of create_filter
        event_filter = {
            'fromBlock': receipt.blockNumber,
            'toBlock': receipt.blockNumber,
            'address': contract.address
        }
        logs = web3.eth.get_logs(event_filter)
        
        events = [contract.events.LogCreated().process_log(log) for log in logs]

        if events:
            for event in events:
                serialized_event = serialize_web3_object(event)
                print("Event emitted:")
                print(json.dumps(serialized_event, indent=2))
                st.info("Event emitted:")
                st.json(serialized_event)
        else:
            print("No events were emitted.")
            st.warning("No events were emitted.")

    except Exception as e:
        error_message = f"Error adding log to blockchain: {e}"
        print(error_message)
        st.error(error_message)
        raise

def format_log_entry(entry):
    # Extract timestamp, method, and hash using regex
    timestamp_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}", entry)
    method_match = re.search(r"Method: (Data Redaction|Data Masking)", entry)
    hash_match = re.search(r"Hash: (\w+)", entry)

    timestamp = timestamp_match.group(0) if timestamp_match else "Unknown"
    method = method_match.group(1) if method_match else "Unknown"
    hash_value = hash_match.group(1) if hash_match else "Unknown"

    return f"""
    <div style="margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
        <p style="margin: 0; font-weight: bold;">{timestamp}</p>
        <p style="margin: 0; color: #555;">Method: <span style="font-weight: bold;">{method}</span></p>
        <p style="margin: 0; color: #888;">Hash: <code>{hash_value}</code></p>
        <p style="margin: 0; color: #777;">{entry}</p>
    </div>
    """


def hash_data(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def log_protection_activity(
    original_text: str, processed_text: str, protection_method: str
):
    timestamp = datetime.now().isoformat()
    redacted_amount = len(original_text) - len(processed_text)
    data_hash = hash_data(processed_text)

    log_message = f"{timestamp} | Method: {protection_method} | Redacted: {redacted_amount} chars | Hash: {data_hash}"

    # Log to file
    logging.info(log_message)

    # Log to blockchain
    try:
        add_audit_log(data_hash, protection_method, timestamp)
        logging.info(f"Log added to blockchain successfully: {data_hash}")
    except Exception as e:
        logging.error(f"Error adding log to blockchain: {e}")


def process_text(text, protection_method, entity_types, custom_words):
    # Process the text based on the protection method
    if protection_method == "Data Redaction":
        result, _ = redact_entities(text, entity_types, custom_words, "High")
    elif protection_method == "Data Masking":
        result = mask_data(text, entity_types, custom_words)
    else:  # Data Anonymization
        result = anonymize_data(text, entity_types, custom_words)

    # Log the protection activity (this now handles both file and blockchain logging)
    log_protection_activity(text, result, protection_method)

    return result


DOWNLOAD_HISTORY_FILE = "download_history.json"
UPLOAD_FOLDER = "uploads"
FILE_RETENTION_DAYS = 30
DEFAULT_ENTITY_TYPES = ["PERSON", "ORG", "GPE", "DATE", "EMAIL"]
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
undo_stack = []
redo_stack = []


def add_email_matcher(nlp):
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    matcher = spacy.matcher.Matcher(nlp.vocab)
    matcher.add("EMAIL", [[{"TEXT": {"REGEX": email_pattern}}]])
    return matcher


@st.cache_resource
def load_nlp_model():
    nlp = spacy.load("en_core_web_sm")
    email_matcher = add_email_matcher(nlp)
    return nlp, email_matcher


nlp, email_matcher = load_nlp_model()


def redact_entities(
    text: str,
    entity_types: List[str],
    custom_words: Optional[List[str]] = None,
    redaction_level: str = "Low",
) -> Tuple[str, List[Tuple[int, int, str, str]]]:
    doc = nlp(text)
    redactions = []

    def partially_redact(word: str, level: str) -> str:
        if level == "High":
            return "[Redacted]"
        elif level == "Medium":
            return word[: len(word) // 2] + "x" * (len(word) - len(word) // 2)
        else:
            return f"{word[:len(word)//2]}-xxxx"

    if custom_words:
        for word in custom_words:
            for match in re.finditer(re.escape(word), text, re.IGNORECASE):
                redactions.append(
                    (match.start(), match.end(), "[REDACTED CUSTOM]", "CUSTOM")
                )

    if "EMAIL" in entity_types:
        email_matches = email_matcher(doc)
        for _, start, end in email_matches:
            redacted = partially_redact(text[start:end], redaction_level)
            redactions.append((start, end, redacted, "EMAIL"))

    for ent in doc.ents:
        if ent.label_ in entity_types:
            redacted = partially_redact(ent.text, redaction_level)
            redactions.append((ent.start_char, ent.end_char, redacted, ent.label_))

    redactions.sort(key=lambda x: x[1], reverse=True)

    for start, end, replacement, label in redactions:
        text = text[:start] + replacement + text[end:]

    return text, redactions


def generate_fake_data(entity_type: str) -> str:
    if entity_type == "PERSON":
        return "John Doe"
    elif entity_type == "ORG":
        return "ACME Corporation"
    elif entity_type == "GPE":
        return "Anytown"
    elif entity_type == "DATE":
        return "01/01/2000"
    elif entity_type == "EMAIL":
        return f"user{random.randint(1000, 9999)}@example.com"
    else:
        return "".join(random.choices(string.ascii_letters + string.digits, k=10))


def mask_data(
    text: str, entity_types: List[str], custom_words: Optional[List[str]] = None
) -> str:
    doc = nlp(text)
    masked_text = text

    if custom_words:
        for word in custom_words:
            masked_text = re.sub(
                re.escape(word),
                generate_fake_data("CUSTOM"),
                masked_text,
                flags=re.IGNORECASE,
            )

    if "EMAIL" in entity_types:
        email_matches = email_matcher(doc)
        for _, start, end in reversed(email_matches):
            fake_email = generate_fake_data("EMAIL")
            masked_text = masked_text[:start] + fake_email + masked_text[end:]

    for ent in reversed(doc.ents):
        if ent.label_ in entity_types:
            fake_data = generate_fake_data(ent.label_)
            masked_text = (
                masked_text[: ent.start_char] + fake_data + masked_text[ent.end_char :]
            )

    return masked_text


def anonymize_data(
    text: str, entity_types: List[str], custom_words: Optional[List[str]] = None
) -> str:
    doc = nlp(text)
    anonymized_text = text

    def generate_anonymous_id() -> str:
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    if custom_words:
        for word in custom_words:
            anonymized_text = re.sub(
                re.escape(word),
                generate_anonymous_id(),
                anonymized_text,
                flags=re.IGNORECASE,
            )

    if "EMAIL" in entity_types:
        email_matches = email_matcher(doc)
        for _, start, end in reversed(email_matches):
            anonymous_id = generate_anonymous_id()
            anonymized_text = (
                anonymized_text[:start]
                + anonymous_id
                + "@anon.com"
                + anonymized_text[end:]
            )

    for ent in reversed(doc.ents):
        if ent.label_ in entity_types:
            anonymous_id = generate_anonymous_id()
            anonymized_text = (
                anonymized_text[: ent.start_char]
                + anonymous_id
                + anonymized_text[ent.end_char :]
            )

    return anonymized_text


def get_entity_counts(text: str) -> Dict[str, int]:
    doc = nlp(text)
    entity_counts = {}
    for ent in doc.ents:
        entity_counts[ent.label_] = entity_counts.get(ent.label_, 0) + 1

    email_matches = email_matcher(doc)
    entity_counts["EMAIL"] = len(email_matches)

    return entity_counts


def get_download_link(text: str, filename: str, link_text: str) -> str:
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    with open(file_path, "w") as f:
        f.write(text)

    with open(file_path, "rb") as f:
        bytes_data = f.read()

    b64 = base64.b64encode(bytes_data).decode()
    return f'<a href="data:file/txt;base64,{b64}" download="{filename}">{link_text}</a>'


def save_download_history(filename: str):
    try:
        history = []
        if os.path.exists(DOWNLOAD_HISTORY_FILE):
            with open(DOWNLOAD_HISTORY_FILE, "r") as f:
                history = json.load(f)

        history.append({"filename": filename, "timestamp": datetime.now().isoformat()})

        with open(DOWNLOAD_HISTORY_FILE, "w") as f:
            json.dump(history, f)
        logging.info(f"Download history updated: {filename}")
    except Exception as e:
        logging.error(f"Error saving download history: {e}")
        st.error(f"Error saving download history: {e}")


def get_download_history() -> List[Dict[str, str]]:
    if os.path.exists(DOWNLOAD_HISTORY_FILE):
        try:
            with open(DOWNLOAD_HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error retrieving download history: {e}")
            st.error(f"Error retrieving download history: {e}")
    return []


def cleanup_old_files():
    try:
        current_time = datetime.now()
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
            if current_time - file_modified > timedelta(days=FILE_RETENTION_DAYS):
                os.remove(file_path)
                logging.info(f"Deleted old file: {filename}")
    except Exception as e:
        logging.error(f"Error during file cleanup: {e}")


def main():
    st.title("RE-DACT")
    st.text("Enhanced Data Protection Tool")
    st.text("Built with Streamlit and spaCy")

    activities = [
        "Data Protection",
        "Entity Analysis",
        "Downloads",
        "About",
        "View Logs",
    ]
    choice = st.sidebar.selectbox("Select Task", activities)

    if choice == "Data Protection":
        st.subheader("Data Protection Options")

        uploaded_file = st.file_uploader("Choose a file", type=["txt", "csv"])
        if uploaded_file is not None:
            rawtext = uploaded_file.getvalue().decode("utf-8")
        else:
            rawtext = st.text_area("Or enter text", "Type Here", height=300)

        all_entity_types = list(nlp.get_pipe("ner").labels) + ["EMAIL"]
        entity_types = st.multiselect(
            "Select entity types to protect",
            all_entity_types,
            default=DEFAULT_ENTITY_TYPES,
        )

        custom_words = st.text_input("Enter custom words to protect (comma-separated)")
        custom_word_list = (
            [word.strip() for word in custom_words.split(",") if word.strip()]
            if custom_words
            else None
        )

        protection_method = st.radio(
            "Select Protection Method",
            ("Data Redaction", "Data Masking", "Data Anonymization"),
        )

        if protection_method == "Data Redaction":
            redaction_level = st.radio(
                "Select Redaction Level", ("High", "Medium", "Low")
            )

        if st.button("Process"):
            if not rawtext or rawtext == "Type Here":
                st.error("Please enter some text to protect or upload a file.")
            elif not entity_types and not custom_word_list:
                st.error(
                    "Please select at least one entity type to protect or enter custom words."
                )
            else:
                with st.spinner("Processing text..."):
                    original_text = rawtext
                    if protection_method == "Data Redaction":
                        result, _ = redact_entities(
                            rawtext, entity_types, custom_word_list, redaction_level
                        )
                    elif protection_method == "Data Masking":
                        result = mask_data(rawtext, entity_types, custom_word_list)
                    else:  # Data Anonymization
                        result = anonymize_data(rawtext, entity_types, custom_word_list)

            # Log the protection activity
            log_protection_activity(original_text, result, protection_method)

            # Log to blockchain
            data_hash = hash_data(result)
            timestamp = datetime.now().isoformat()
            add_audit_log(data_hash, protection_method, timestamp)

            st.write("Processed Text:")
            st.write(result)

            filename = f"{protection_method.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            st.markdown(
                get_download_link(
                    result, filename, f"Download {protection_method} Text"
                ),
                unsafe_allow_html=True,
            )
            save_download_history(filename)
        else:
            st.write("Please process the text to see the results.")

    elif choice == "Entity Analysis":
        st.subheader("Entity Analysis")
        rawtext = st.text_area("Enter text for analysis", "Type Here", height=300)
        if st.button("Analyze"):
            if not rawtext or rawtext == "Type Here":
                st.error("Please enter some text to analyze.")
            else:
                with st.spinner("Analyzing text..."):
                    entity_counts = get_entity_counts(rawtext)
                st.write("Entity Counts:")
                for entity, count in entity_counts.items():
                    st.write(f"{entity}: {count}")

    elif choice == "Downloads":
        st.subheader("Download History")
        history = get_download_history()
        if history:
            for item in history:
                st.write(f"{item['timestamp']}: {item['filename']}")
                file_path = os.path.join(UPLOAD_FOLDER, item["filename"])
                if os.path.exists(file_path):
                    with open(file_path, "r") as f:
                        st.download_button(
                            f"Download {item['filename']}", f.read(), item["filename"]
                        )
                else:
                    st.write(f"File {item['filename']} no longer exists.")
        else:
            st.write("No download history available.")

    # elif choice == "View Logs":
    #   st.subheader("View Logs")

    # Path to your log file
    #  log_file_path = ".//data_protection_tool.log"

    # if os.path.exists(log_file_path):
    #    with open(log_file_path, 'r') as file:
    #       log_entries = file.readlines()

    # Display log entries with custom formatting
    #  for entry in log_entries:
    #     formatted_entry = format_log_entry(entry.strip())
    #    st.markdown(formatted_entry, unsafe_allow_html=True)
    # else:
    #   st.error("Log file not found.")

    elif choice == "View Logs":
        st.subheader("View Blockchain Logs")

    if st.button("Fetch Blockchain Logs"):
        try:
            # Get the latest block number
            latest_block = web3.eth.get_block('latest')['number']
            
            # Fetch logs for the entire blockchain history
            event_filter = {
                'fromBlock': 0,
                'toBlock': latest_block,
                'address': contract.address
            }
            logs = web3.eth.get_logs(event_filter)
            
            # Process the logs
            events = [contract.events.LogCreated().process_log(log) for log in logs]

            if events:
                for event in events:
                    # Extract event data
                    data_hash = event['args']['hash']
                    action = event['args']['action']
                    timestamp = event['args']['timestamp']
                    
                    # Display event data
                    st.markdown(
                        f"""
                        ---
                        **Transaction Hash**: `{event['transactionHash'].hex()}`  
                        **Block Number**: {event['blockNumber']}  
                        **Hash**: {data_hash}  
                        **Action**: {action}  
                        **Timestamp**: {timestamp}
                        """
                    )
            else:
                st.write("No logs found on the blockchain.")
        except Exception as e:
            st.error(f"Error fetching logs: {e}")
            print(f"Error details: {str(e)}") 

    elif choice == "About":
        st.subheader("About")
        st.write(
            "This is an enhanced data protection tool built with Streamlit and spaCy."
        )
        st.write("Features include:")
        st.write(
            "- Data Redaction: Obscures or blacks out sensitive or confidential information in a document"
        )
        st.write(
            "- Data Masking: Replaces authentic information with fake one, but with the same structure"
        )
        st.write(
            "- Data Anonymization: Erases/encrypts identifiers in a document so identification is not possible"
        )
        st.write("- Entity analysis")
        st.write("- Download history and re-download of previous files")
        st.write("- File upload support")
        st.write("- Email detection and protection")

    # Run cleanup job
    cleanup_old_files()


if __name__ == "__main__":
    main()
