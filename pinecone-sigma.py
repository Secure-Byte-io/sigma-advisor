import yaml
import sys
from pinecone import Pinecone
import os
from langchain_openai import OpenAIEmbeddings  # or another embedding model
import argparse

# Initialize embedding model
embeddings = OpenAIEmbeddings(
    openai_api_key=os.environ.get("OPENAI_API_KEY"),
    model="text-embedding-3-large",
    dimensions=3072
)

# Initialize Pinecone
pc = Pinecone(api_key=os.environ.get("PINECONE_API_KEY"))
index = pc.Index("sigma-rule-index")

def process_sigma_file(file_path, input_folder):
    file_path = os.path.abspath(file_path)
    with open(file_path, 'r') as file:
        rule = yaml.safe_load(file)
    
    # Create a text representation of the rule
    rule_text = f"Title: {rule.get('title', '')}\n"
    rule_text += f"Description: {rule.get('description', '')}\n"
    rule_text += f"Detection: {str(rule.get('detection', ''))}\n"
    # Add other fields as needed

    # Generate embedding
    vector = embeddings.embed_query(rule_text)
    
    # Prepare metadata
    # Construct GitHub link from local file path
    rel_path = os.path.relpath(file_path, input_folder)
    github_link = f"https://github.com/SigmaHQ/sigma/blob/master/{rel_path}"
    metadata = {
        "title": rule.get("title", ""),
        "tags": rule.get("tags", []),
        "rule": yaml.dump(rule),
        "link": github_link,
        "file_name": os.path.basename(file_path),
    }
    # Upsert to Pinecone
    index.upsert([(rule.get("id"), vector, metadata)])

# Process directory of rules
def process_directory(directory_path):
    for root, _, files in os.walk(directory_path):
        for filename in files:
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                try:
                    process_sigma_file(os.path.join(root, filename), directory_path)
                except Exception as e:
                    print(f"Error processing {filename}: {e}")
                    continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process Sigma rules and upload to Pinecone."
    )
    parser.add_argument(
        "input_folder",
        type=str,
        help="Path to the folder containing Sigma rules."
    )
    args = parser.parse_args()
    process_directory(args.input_folder)