import os
from dotenv import load_dotenv
from langchain_openai import OpenAIEmbeddings
from langchain.embeddings.azure_openai import AzureOpenAIEmbeddings
from annoy import AnnoyIndex
from sentence_transformers import SentenceTransformer #, util

# Load environment variables
load_dotenv()

#embeddings = OpenAIEmbeddings(openai_api_key=os.getenv('OPENAI_API_KEY'))
embeddings = AzureOpenAIEmbeddings(
    deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"),
    model="text-embedding-ada-002",
    openai_api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    openai_api_base=os.getenv("AZURE_OPENAI_ENDPOINT"),
    openai_api_version="2023-05-15"  # Check the latest supported version for your setup
)
model = SentenceTransformer('sentence-transformers/allenai-specter', device='cpu')

def get_file_embeddings(file_name, file_content):
    try:
        ret = embeddings.embed_query(file_content)
        return ret
    except Exception as e:
        print(f"Error in embedding file: {file_name} - {e}")
        return None


def build_embeddings(repo_files, name):
    embeddings_dict = {}
    embeddings_dict2 = {}
    i = 0
    s = set()
    for file_name, file_content in repo_files.items():
        e = get_file_embeddings(file_name, file_content)
        if (e is None):
            print ("Error in embedding file: ")
            print (file_name)
            s.add(file_name)
        else:
            embeddings_dict[file_name] = e   # embedding generated using OpenAI
            embeddings_dict2[file_name] = model.encode(file_content)   # embedding generated using A Sentence Transformer model (allenai-specter)
        i+=1
        if (i%100 == 0):
            print ("No of files processed: " + str(i))


    t = AnnoyIndex(1536, 'angular')
    t2 = AnnoyIndex(768, 'angular')
    index_map = {}
    i = 0
    for file in embeddings_dict:
        t.add_item(i, embeddings_dict[file])
        t2.add_item(i, embeddings_dict2[file])
        index_map[i] = file
        i+=1

    t.build(len(repo_files))
    name1= name + "_ada.ann"
    t.save(name1)
    t2.build(len(repo_files))
    name2 = name + "_specter.ann"
    t2.save(name2)

    with open('index_map' + name + '.txt', 'w') as f:
        for idx, path in index_map.items():
            f.write(f'{idx}\t{path}\n')