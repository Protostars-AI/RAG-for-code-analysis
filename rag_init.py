"""
Get repo data from the endpoint
"""
import os
import json
import time
import base64
import logging
import requests
import datetime
import pandas as pd
from dotenv import load_dotenv
from celery import Celery
from flask import Flask, request, jsonify
from flask_cors import CORS
from sentence_transformers import SentenceTransformer
from langchain_openai import OpenAIEmbeddings
from openai import AzureOpenAI
from build_embeddings import build_embeddings, get_file_embeddings
from search import query_top_files_ada, query_top_files_large_3, query_top_files_specter, get_model_files_scores

# Load environment variables
load_dotenv()

# Initialize embeddings and model
#embeddings = OpenAIEmbeddings(openai_api_key=os.getenv('OPENAI_API_KEY'))
deployment_name=os.getenv("AZURE_DEPLOYMENT_NAME")
client = AzureOpenAI(
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2023-05-15",  # Check the latest supported version for your setup
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
)
model = SentenceTransformer('sentence-transformers/allenai-specter', device='cpu')

# Flask application setup
app = Flask(__name__)
cors = CORS(app, resources={r"/initiate": {"origins": "*"}})

# Celery configuration
def make_celery(app):
    celery = Celery(
        app.import_name,
        broker='redis://localhost:6379/0',
        backend='redis://localhost:6379/0'
    )
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)

# Load OWASP data
owasp_df = pd.read_csv('OWASP Controls - Application Security.csv')
owasp_df = owasp_df[~owasp_df['req_description'].str.contains('\[DELETED')]
owasp_df['req_description'] = owasp_df['req_description'].str.replace(r'\s*\([^)]*\)', '', regex=True)

# Decode JSON object
def decode_json_object(array):
    files = {}
    for file_name, file_content in array.items():
        if file_name.endswith(('.py', '.sh', '.java', '.php', '.js', '.htm', '.html', '.vue')):
            string_base64 = array[file_name]['content']
            decodedBytes = base64.b64decode(string_base64)
            files[file_name] = decodedBytes.decode("utf-8")
    return files

# Celery task
@celery.task(bind=True, max_retries=0)
def background_code_matching(self, repo, repo_id):
    logging.info(f"[{datetime.datetime.now()}]Task initiated with job id: {self.request.id}")
    try:
        job_id = self.request.id
        repo_id = str(repo_id)
        repo_files = decode_json_object(repo)
        section_result = {}
        build_embeddings(repo_files, repo_id)
        
        for section in owasp_df['section_name'].unique():
            reqs_list = list(owasp_df[owasp_df['section_name'] == section]['req_description'])
            req_str = ' '.join(reqs_list)
            query = req_str
            depth = 3 #get_total_files(repo_id)
            #results_large_3 = query_top_files_large_3(query, depth, repo_id)
            results_specter = query_top_files_specter(query, depth, repo_id)
            model_list = get_model_files_scores(results_specter)
            
            #common_files_with_avg_score = get_common_files_with_avg_score(results_ada, results_specter)
            #unique_model = get_unique_files(results_ada, results_specter)
            unique_model = []
            result_dict = {'common_files': model_list, 'only_one_model': unique_model}
            section_result[section] = result_dict
        
        # Save the section_result dictionary to a .json file
        with open(f'section_result_{repo_id}.json', 'w') as json_file:
            json.dump(section_result, json_file, indent=4)
        rag_output = section_result
        # save rag output so I can test later
        with open(f'rag_output_top_{depth}_{repo_id}.json', 'w') as json_file:
            json.dump(rag_output, json_file, indent=4)
        data = {"rag_output" :rag_output,
                "repo_files": repo}
        r1 = requests.post(f'https://code-compliance.protostars.ai/code-compliance', json=data)
        code_comp_task_id = json.loads(r1.text)['task_id'] # get task id from the response
        logging.info(f"Response from code compliance success with task id: {code_comp_task_id}")
        r2 = requests.get(f"https://code-compliance.protostars.ai/get_results/{code_comp_task_id}")
        state = json.loads(r2.text)['state']
        # loop and check the state of the task
        while (state != 'SUCCESS'):
            time.sleep(120)
            r2 = requests.get(f"https://code-compliance.protostars.ai/get_results/{code_comp_task_id}")
            state = json.loads(r2.text)['state']
        # when its done send the results to the server endpoint
        return json.loads(r2.text)['result']
    except Exception as e:
        logging.error(f"Task failed: {e}")
        raise self.retry(exc=e, countdown=60, max_retries=0)
    

# Flask routes
@app.route('/initiate_rag', methods=['POST'])
def initiate():
    data = request.json
    repo = data['repository_tree']
    repo_id = data['id']
    job = background_code_matching.apply_async(args=(repo,repo_id))
    return jsonify({'task_id': job.id}), 202

@app.route('/results_rag/<task_id>', methods=['GET'])
def get_results(task_id):
    task = background_code_matching.AsyncResult(task_id)
    if task.state == 'PENDING':
        response = {
            'state': task.state
        }
    elif task.state != 'FAILURE':
        response = {
            'state': task.state,
            'result': task.result
        }
    else:
        response = {
            'state': task.state,
            'error': str(task.info)  # this is the exception raised
        }
    return jsonify(response)


if __name__== "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)