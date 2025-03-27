from fastapi import FastAPI, HTTPException, Depends
from pydantic import EmailStr
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
from datetime import datetime, timedelta
import psycopg2
import asyncio
from sentence_transformers import SentenceTransformer
from utils.auth import get_current_user, create_access_token, get_password_hash, verify_password
import openai
from transformers import pipeline
import re
import os

load_dotenv()


from utils.auth import create_access_token, get_current_user, verify_password, get_password_hash
from utils.logger import logger


qa_pipeline = pipeline("question-answering", model="deepset/roberta-base-squad2")


app = FastAPI()


DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")


try:
    conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
    cursor = conn.cursor()
    logger.info("Connected to PostgreSQL database successfully.")
except Exception as e:
    logger.error(f"Database connection error: {str(e)}")
    raise e

model = SentenceTransformer('all-MiniLM-L6-v2')

class User(BaseModel):
    username: str
    password: str
    email: EmailStr  # Ensures valid email format
    
class UserLogin(BaseModel):
    username: str
    password: str

class Document(BaseModel):
    document_id: str
    content: str

class DocumentSelection(BaseModel):
    document_ids: List[str]  
    action: str 

class Question(BaseModel):
    question: str
    document_ids: Optional[List[str]] = None



@app.post("/api/v1//register")
async def register_user(user: User):
    hashed_password = get_password_hash(user.password)
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s)",
            (user.username, hashed_password, user.email)
        )
        conn.commit()
        logger.info(f"User {user.username} registered successfully.")
        return {"message": "User registered successfully"}
    except Exception as e:
        if "email" in str(e):  
            raise HTTPException(status_code=400, detail="Email already registered")
        elif "username" in str(e):  
            raise HTTPException(status_code=400, detail="Username already exists")
        else:
            logger.error(f"User registration error: {str(e)}")
            raise HTTPException(status_code=500, detail="An error occurred during registration")




@app.post("/api/v1//login")
async def login_user(user: UserLogin):
    
    cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (user.username,))
    user_data = cursor.fetchone()

    
    if not user_data or not verify_password(user.password, user_data[1]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}





@app.post("/api/v1//ingest")
async def ingest_document(doc: Document, username: str = Depends(get_current_user)):
  
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    user_data = cursor.fetchone()

    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    user_id = user_data[0] 

    embedding = await asyncio.to_thread(model.encode, doc.content)
    embedding_list = embedding.tolist()  

    
    cursor.execute(
        "INSERT INTO document_embeddings (document_id, embedding, content, user_id, selected) VALUES (%s, %s, %s, %s, %s)",
        (doc.document_id, embedding_list, doc.content, user_id, False)
    )
    conn.commit()

    return {"message": "Document ingested successfully, and not selected by default."}




@app.get("/api/v1/documents")
def list_user_documents(username: str = Depends(get_current_user)):
    
    cursor.execute("SELECT document_id, content FROM document_embeddings WHERE user_id = (SELECT id FROM users WHERE username = %s)", (username,))
    documents = cursor.fetchall()

    if not documents:
        return {"message": "No documents available for the current user."}

    response = [{"document_id": doc[0], "content_excerpt": doc[1][:100] + "..."} for doc in documents]
    return {"user": username, "documents": response}


@app.post("/api/v1/select-documents")
def select_documents(selection: DocumentSelection, username: str = Depends(get_current_user)):
    
    if selection.action not in ["include", "exclude"]:
        raise HTTPException(status_code=400, detail="Invalid action. Must be 'include' or 'exclude'.")

    for doc_id in selection.document_ids:
        status = "true" if selection.action == "include" else "false"
        cursor.execute(
            "UPDATE document_embeddings SET selected=%s WHERE document_id=%s AND user_id = (SELECT id FROM users WHERE username = %s)",
            (status, doc_id, username)
        )
        conn.commit()

    return {"message": f"Documents have been successfully {selection.action}d for retrieval."}


@app.get("/api/v1/selected-documents")
def view_selected_documents(username: str = Depends(get_current_user)):
    
    try:
       
        cursor.execute(
            "SELECT document_id, content FROM document_embeddings WHERE user_id = (SELECT id FROM users WHERE username = %s) AND selected = true",
            (username,)
        )
        documents = cursor.fetchall()

        
        if not documents:
            return {"message": "No documents selected for retrieval."}

        
        response = [{"document_id": doc[0], "content_excerpt": doc[1][:100] + "..."} for doc in documents]
        return {"user": username, "selected_documents": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")



def split_question(question):
    
    sub_questions = re.split(r'\band\b|\bor\b', question)
    return [q.strip() for q in sub_questions]

@app.post("/api/v1/query")
async def answer_question(question: Question, username: str = Depends(get_current_user)):
   
    try:
        
        cursor.execute(
            "SELECT embedding, content FROM document_embeddings WHERE user_id = (SELECT id FROM users WHERE username = %s) AND selected=true",
            (username,)
        )
        rows = cursor.fetchall()

        if not rows:
            raise HTTPException(status_code=404, detail="No selected documents found for retrieval.")

       
        combined_context = " ".join([row[1] for row in rows])

        sub_questions = split_question(question.question)

        answers = []
        for sub_question in sub_questions:
            answer = qa_pipeline(
                question=sub_question,
                context=combined_context,
                max_answer_len=100,
                handle_impossible_answer=True
            )
            answers.append(f"{sub_question}: {answer['answer']}")

        cursor.execute("UPDATE document_embeddings SET selected = false WHERE user_id = (SELECT id FROM users WHERE username = %s)", (username,))
        conn.commit()

        return {"answer": " ".join(answers)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    