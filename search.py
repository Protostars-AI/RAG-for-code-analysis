from interpreter import interpreter
import os
import math
from dotenv import load_dotenv
#from langchain_openai import OpenAIEmbeddings
from openai import AzureOpenAI
from annoy import AnnoyIndex
from sentence_transformers import SentenceTransformer

# Load environment variables
load_dotenv()

#embeddings = OpenAIEmbeddings(openai_api_key=os.getenv('OPENAI_API_KEY'))
deployment_name=os.getenv("AZURE_MODEL_NAME")
client = AzureOpenAI(
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2023-05-15",  # Check the latest supported version for your setup
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
)
model = SentenceTransformer('sentence-transformers/allenai-specter', device='cpu')

EMBEDDING_DIM = 1536
# Get query embeddings
def get_embeddings_for_text(text):
    return client.embeddings.create(input=text, model=deployment_name)

def load_index_map(name):
    index_map = {}
    files_count = 0
    with open('index_map' + name + '.txt', 'r') as f:
        for line in f:
            idx, path = line.strip().split('	')
            index_map[int(idx)] = path
    return index_map

def get_total_files(name):
    with open('index_map' + name + '.txt', 'r') as f:
        total_files = sum(1 for _ in f)
    return total_files

def query_top_files(query, top_n, name):
    # Load annoy index and index map
    t = AnnoyIndex(EMBEDDING_DIM, 'angular')  # Angular distance ranges between 0 radians to approximatly 3.1416 rads 
    t.load(name+'_ada.ann')
    index_map = load_index_map(name)
    # Get embeddings for the query
    query_embedding = get_embeddings_for_text(query)
    # Search in the Annoy index
    indices, distances = t.get_nns_by_vector(query_embedding, top_n, include_distances=True)
    similarities = [math.cos(d) for d in distances if d > 0.5]     # filter out the similarity score to include only scores above 0.5
    # Fetch file paths for these indices
    files = [(index_map[idx], dist) for idx, dist in zip(indices, similarities)]
    return files

def query_top_files_specter(query, top_n, name):    # we can query total_vectors which queries all the files, create a function to get no. of files in the repo
    # Load annoy index and index map
    t = AnnoyIndex(768, 'angular')
    t.load(name + '_specter.ann')
    index_map = load_index_map(name)
    # Get embeddings for the query
    query_embedding = model.encode(query)
    # Search in the Annoy index
    indices, distances = t.get_nns_by_vector(query_embedding, top_n, include_distances=True)
    similarities = [math.cos(d) for d in distances if d > 0.5]     # filter out the similarity score to include only scores above 0.5
    # Fetch file paths for these indices
    files = [(index_map[idx], dist) for idx, dist in zip(indices, similarities)]
    return files


# create a function to get the retrieved files in both models and return the file names with score from both models
def get_common_files_with_avg_score(results_ada, results_specter):
    ada_dict = {os.path.basename(path): score for path, score in results_ada}
    specter_dict = {os.path.basename(path): score for path, score in results_specter}
    
    common_files = []
    for file_name in ada_dict:
        if file_name in specter_dict:
            avg_score = (ada_dict[file_name] + specter_dict[file_name]) / 2
            common_files.append((file_name, avg_score))
    
    return common_files


# create a function to get files retrived by only one model and not by the other
def get_unique_files(results_ada, results_specter):
    ada_files = {os.path.basename(path): score for path, score in results_ada}
    specter_files = {os.path.basename(path): score for path, score in results_specter}
    
    unique_ada = [(path, score) for path, score in ada_files.items() if path not in specter_files]
    unique_specter = [(path, score) for path, score in specter_files.items() if path not in ada_files]
    unique_model = unique_ada + unique_specter
    
    return unique_model