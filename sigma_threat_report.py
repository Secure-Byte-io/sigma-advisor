import requests
from bs4 import BeautifulSoup
import html2text
import json
import argparse
from autogen import AssistantAgent, UserProxyAgent
import time
import re
from pinecone import Pinecone
import openai
from openai import OpenAI
import os

# Configure OpenAI API
config_list = [
    {
        "model": "gpt-4.1",
        "api_key": os.environ.get("OPENAI_API_KEY")
    }
]

# Pinecone configuration
PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
if not PINECONE_API_KEY:
    raise ValueError("PINECONE_API_KEY environment variable not set.")
PINECONE_INDEX = "sigma-rule-index"  # Set your index name here

# OpenAI embedding model
OPENAI_EMBEDDING_MODEL = "text-embedding-3-large"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable not set.")

def convert_url_to_markdown(url):
    """Download content from URL and convert to markdown."""
    try:
        headers = {
            'User-Agent': ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/91.0.4472.124 Safari/537.36'),
            'Accept': ('text/html,application/xhtml+xml,application/xml;'
                      'q=0.9,image/webp,*/*;q=0.8'),
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=30)
        
        # Check for Cloudflare protection
        if (response.status_code == 503 and
                'cloudflare' in response.headers.get('Server', '').lower()):
            retry_after = int(response.headers.get('Retry-After', 3600))
            time.sleep(retry_after)
            response = session.get(url, headers=headers, timeout=30)
        
        response.raise_for_status()
        
        if response.encoding == 'ISO-8859-1':
            response.encoding = response.apparent_encoding
        
        soup = BeautifulSoup(response.text, 'html.parser')
        h = html2text.HTML2Text()
        h.ignore_links = False
        h.ignore_images = False
        markdown_content = h.handle(str(soup))
        
        return markdown_content
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None

def analyze_threat_report(content):
    """Use AutoGen agents to analyze the threat report and structure it."""
    
    # Debug: Check content length and preview
    print(f"Content length: {len(content)} characters")
    print(f"Content preview (first 500 chars): {content[:500]}")
    
    assistant = AssistantAgent(
        name="threat_analyzer",
        llm_config={"config_list": config_list},
        system_message="""You are a cybersecurity threat analysis expert. 
        Your task is to analyze threat reports, security incidents, malware reports, or any cybersecurity content and break it down into attack phases.
        
        You must ALWAYS respond with a valid JSON object following this exact structure:
        {
            "phases": [
                {
                    "name": "phase_name",
                    "summary": "detailed summary of the phase",
                    "ttp": "Attacker Tactics, Techniques and Procedures (TTP)",
                }
            ]
        }
        
        Do not return an empty phases array unless the content is completely unrelated to cybersecurity."""
    )
    
    user_proxy = UserProxyAgent(
        name="user_proxy",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=1,
        code_execution_config=False,  # Disable code execution
        llm_config=False  # Disable LLM for user proxy
    )
    
    # Use more content but still limit to avoid token limits
    content_to_analyze = content
    
    analysis_task = f"""Analyze this content and identify cybersecurity threat phases, attack techniques, or security incidents.
    Break down the content into logical phases of an attack or security event.
    
    For each phase you identify, extract:
    1. Phase name (use standard attack phases when possible)
    2. detailed summary of the phase
    3. Attacker Tactics, Techniques and Procedures (TTP)
    
    Return ONLY a JSON object with your analysis. No explanations or markdown formatting.
    Content to analyze:
    {content_to_analyze}
    """
    
    print("Sending task to assistant...")
    print(f"Task length: {len(analysis_task)} characters")
    
    # Use initiate_chat instead of send for better control
    chat_result = user_proxy.initiate_chat(
        assistant,
        message=analysis_task,
        max_turns=1
    )
    
    assistant_response = None
    
    if hasattr(chat_result, 'summary') and chat_result.summary:
        assistant_response = chat_result.summary
    
    if assistant_response:
        try:
            return json.loads(assistant_response)
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            print(f"Raw response: {repr(assistant_response)}")
            return None
    else:
        print("No assistant response found")
        return None

def get_openai_embedding(text):
    """Get embedding for text using OpenAI's text-embedding-3-large model."""
    client = OpenAI(api_key=OPENAI_API_KEY)
    response = client.embeddings.create(
        input=text,
        model=OPENAI_EMBEDDING_MODEL
    )
    return response.data[0].embedding

def find_sigma_detections_with_embeddings(phases, top_k=5):
    """Query Pinecone for relevant sigma detections using OpenAI embeddings."""
    pc = Pinecone(api_key=PINECONE_API_KEY)
    index = pc.Index(PINECONE_INDEX)
    all_phase_candidates = []
    for phase in phases:
        ttp = phase.get("ttp", "")
        query_text = ttp if ttp else phase.get("summary", "")
        if not query_text:
            all_phase_candidates.append([])
            continue
        try:
            query_vector = get_openai_embedding(query_text)
            pinecone_results = index.query(vector=query_vector, top_k=top_k, include_metadata=True)
            candidates = []
            for match in pinecone_results.get("matches", []):
                meta = match["metadata"]
                candidates.append({
                    "sigma_rule_name": meta.get("title"),
                    "sigma_rule_link": meta.get("link"),
                    "file_name": meta.get("file_name"),
                    "rule": meta.get("rule"),
                    "score": match.get("score", 0)
                })
            all_phase_candidates.append(candidates)
        except Exception as e:
            print(f"Pinecone query error: {e}")
            all_phase_candidates.append([])
    return all_phase_candidates

def select_sigma_detections_for_phase(phase, candidates):
    """Use an LLM agent to select and justify sigma detections for a phase."""
    # Compose a prompt for the LLM
    prompt = f"""
    You are a cybersecurity detection engineer. Given the following attack phase description and a list of candidate sigma detections, select the most relevant detections and explain why each is useful for detecting this phase.

    Phase name: {phase.get('name', '')}
    Phase summary: {phase.get('summary', '')}
    TTP: {phase.get('ttp', '')}

    Candidate sigma detections:
    """
    for idx, c in enumerate(candidates):
        prompt += f"\n{idx+1}. Title: {c['sigma_rule_name']}, URL: {c['sigma_rule_link']}"
        prompt += f"\n   Rule: {c['rule'][:200]}..."  # Truncate rule for prompt
    prompt += "\n\nFor each detection, return a JSON object with: title, url, and a reason why this detection is chosen. Return a list of such objects."

    # Use OpenAI chat completion for reasoning (new API)
    client = OpenAI(api_key=OPENAI_API_KEY)
    response = client.chat.completions.create(
        model="gpt-4o",  # or gpt-4-turbo if available
        messages=[
            {"role": "system", "content": "You are a cybersecurity detection engineer."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=512,
        temperature=0.2
    )
    # Extract JSON from response
    import json as _json
    text = response.choices[0].message.content
    try:
        detections = _json.loads(text)
    except Exception:
        # Fallback: try to extract JSON from text
        import re
        match = re.search(r'\[.*\]', text, re.DOTALL)
        if match:
            detections = _json.loads(match.group(0))
        else:
            detections = []
    return detections

def enrich_with_sigma_detections_v2(analysis_json):
    """Extend the analysis JSON with a list of sigma detections for each phase."""
    phases = analysis_json.get("phases", [])
    all_candidates = find_sigma_detections_with_embeddings(phases, top_k=5)
    for i, phase in enumerate(phases):
        candidates = all_candidates[i]
        if candidates:
            detections = select_sigma_detections_for_phase(phase, candidates)
            phase["sigma_detections"] = detections
        else:
            phase["sigma_detections"] = []
    return analysis_json

def main():
    parser = argparse.ArgumentParser(
        description='Analyze a threat report from a URL'
    )
    parser.add_argument('url', help='URL of the threat report to analyze')
    args = parser.parse_args()
    
    markdown_content = convert_url_to_markdown(args.url)
    if not markdown_content:
        print("Failed to fetch content from URL")
        return
    
    analysis_result = analyze_threat_report(markdown_content)
    if analysis_result:
        # Enrich with sigma detections using new agent logic
        enriched_result = enrich_with_sigma_detections_v2(analysis_result)
        with open('threat_analysis.json', 'w') as f:
            json.dump(enriched_result, f, indent=2)
        print("Analysis complete. Results saved to threat_analysis.json")

    else:
        print("Failed to analyze the threat report")

if __name__ == "__main__":
    main()