# Sigma Advisor
![Sigma Advisor](sigma-advisor.png)
Sigma Advisor is an AI-powered security analysis tool that bridges the gap between threat intelligence and detection engineering. The tool streamlines security operations by:

- Automatically analyzing threat reports to identify relevant detection opportunities
- Mapping threat behaviors to public or private Sigma detection rules
- Prioritizing Sigma rules based on their relevance to specific threats

Sigma Advisor empowers security teams to rapidly transform threat intelligence into effective detection capabilities, ensuring organizations can quickly adapt their security posture to emerging threats with the right Sigma rules.

## Preparation
Sigma Advisor leverages a Pinecone database to store Sigma rules. This database can be populated with your own Sigma rules or you can use the public Sigma rules.
First, you need to craete a [Pinecone database](https://www.pinecone.io/) with the following properties:
- name `sigma-rule-index` 
- Choose external embedding model `text-embedding-3-large` by clicking on the blue magic stick with the label Autofill values from model.

## Usage

Virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

Store your API keys into environment variables:
```bash
export PINECONE_API_KEY=<your_pinecone_api_key>
export OPENAI_API_KEY=<your_openai_api_key>
```

Load the sigma rules into the Pinecone database:
```bash
python3 pinecone-sigma.py <path_to_sigma_rules>
```

Analyze a threat report:
```bash
python3 sigma_threat_report.py <url_of_threat_report>
```

This will output a JSON file with the results. An example output is provided in the `threat_analysis.json` file.

## Call to Action

Are you interested in building advanced AI agent workflows for security operations? If you want to learn how to design, implement, and scale solutions like Sigma Advisor, reach out to us! We offer specialized training and consulting to help you elevate your security team's capabilities.

👉 [Contact us!](https://secure-byte.io/contact)

