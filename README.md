﻿# RAG_Project
# Project Setup Guide -
1. Download the project and set up a virtual environment <br />
  1.1. Clone The repository <br />
  1.2. Create a Virtual Environment using the below command <br />
    python -m venv venv  <br />
  1.3. Activate the Virtual Environment<br />
    venv\Scripts\activate  <br />
  1.4. Install Project Dependencies<br />
    pip install -r requirements.txt  <br />

2. Set up the .env file<br />
   2.1 In the project root directory, create a file named .env and add the following environment variables:<br />
        DB_NAME=your_database_name  <br />
        DB_USER=your_database_user  <br />
        DB_PASSWORD=your_database_password  <br />
        DB_HOST=localhost  # or your host address  <br />
        DB_PORT=5432       # default PostgreSQL port <br />

3.  Install PostgreSQL and Set Up the Database<br />
    3.1 Download and Install PostgreSQL:<br />
    3.2 Open pgAdmin (PostgreSQL Admin Tool)<br />
    3.3 Launch pgAdmin and log in using the credentials you set during installation.<br />
    3.4 Create a new database by following these steps:<br />
        Right-click on Databases in the left panel and select Create > Database.<br />
        Enter a database name (e.g., mydatabase) and click Save.<br />
        Plug the Database Values into the .env File<br />
        Update your .env file with the details of the database you just created.<br />

4. Run the Database Setup Script<br />
  Using pgAdmin:<br />
   Open pgAdmin and connect to your database.<br />
   Navigate to the Query Tool (you can find it under the Tools tab).<br />
   Open the file database_setup.sql from the project folder and run the SQL commands to create the following tables:<br />
      users<br />
      document_embeddings<br />
  Alternatively, you can also run the script using the command line:<br />
      psql -U your_database_user -d mydatabase -f database_setup.sql  <br />
   Replace your_database_user with your PostgreSQL username.<br />
   Replace mydatabase with the name of the database you created.<br />

5. Run the application <br />
    uvicorn main:app --reload  <br />
  This will start the server at http://127.0.0.1:8000. <br />
  YOU CAN ACCESS THE API DOCUMENTATION AT:<br />
    Swagger UI: http://127.0.0.1:8000/docs<br />

6. Endpoints meaning -<br />
    6.1. Register: Registers the user<br />
    6.2  Login:  Logs in the user providing a bearer token<br />
    6.3  Ingest: Puts a document in the document_embeddings database for the current user<br />
    6.4  Documents: Endpoint to view the all the documents for the current user<br />
    6.5  Select-Documents: Allows the user to select the documents for RAG retrieval<br />
    6.6  Selected-Documents: Allows the user to view the selected documents<br />
    6.7  Query: Allows the user to ask a question<br />

   NOTE: AFTER EVERY QUERY, YOU NEED TO SELECT THE DOCUMENTS AGAIN BY USING THE "/api/v1/select-documents" ENDPOINT<br />

6. While trying out the endpoints such as "/api/v1/ingest", "/api/v1/select-documents" , "/api/v1/selected-documents", "/api/v1/documents", "/api/v1/query" you need to also send the bearer token as the authorization which you recieve when hitting the login endpoint.<br />

# FEATURES 

User Management System<br />
User Registration and Authentication:<br />
Users can register with a username, password, and email. The password is securely stored by hashing it with bcrypt to ensure user privacy and security.<br />

Once registered, users can log in to obtain a JWT (JSON Web Token). This token authenticates users and grants access to protected endpoints.<br />

Authentication Middleware<br />
The project uses dependencies like get_current_user to protect API routes. Only authenticated users with a valid token can access endpoints like ingesting documents or querying selected documents.<br />

Retrieval-Augmented Generation (RAG)<br />
RAG combines document retrieval and machine learning-based question answering to enhance query responses:<br />

Users can ingest and embed documents into a PostgreSQL database. The project uses SentenceTransformer (all-MiniLM-L6-v2) to generate vector embeddings for these documents.<br />

Users can select documents for answering queries.<br />

During a query, the system retrieves only the selected documents, processes them as the context, and uses a QA pipeline (deepset/roberta-base-squad2) to provide an accurate answer.<br />

# Justification for the Choice of Retrieval Algorithms and Embedding Models<br />

1. SentenceTransformer ('all-MiniLM-L6-v2') as the Embedding Model<br />
Model Used: all-MiniLM-L6-v2 from the SentenceTransformer library.<br />
Why This Model Was Chosen<br />

Efficient Embedding Generation: This model is well-suited for generating semantic embeddings of textual data. It converts document content into dense vector embeddings, preserving semantic meaning.<br />

Lightweight and Fast: Compared to larger models like BERT or RoBERTa, all-MiniLM-L6-v2 is faster and consumes fewer resources, making it efficient for real-time applications. Despite being smaller, it offers competitive performance on tasks like information retrieval and semantic similarity.<br />

High Accuracy for Sentence-Level Embeddings: This model is optimized for sentence and short-text embeddings, aligning well with the task of embedding document excerpts and later retrieving them based on semantic similarity.<br />

Justification:<br />
For this project, where multiple users may ingest and query several documents, the model’s balance between speed and semantic understanding makes it a great choice. It ensures that even with smaller embeddings, the model can effectively capture the meaning of document content.<br />

2. Retrieval Strategy: User Selection + Filtering-Based Retrieval<br />
Manual Document Selection: Users can include/exclude documents before querying, reducing noise and improving relevance<br />

Efficient Retrieval: Embeddings are pre-computed and stored, ensuring quick filtering and document access.<br />

