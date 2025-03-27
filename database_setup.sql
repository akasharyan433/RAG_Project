
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);


CREATE TABLE document_embeddings (
    id SERIAL PRIMARY KEY,
    document_id VARCHAR(255) NOT NULL,
    embedding FLOAT8[] NOT NULL,  -- Stores embeddings as arrays
    content TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    selected BOOLEAN DEFAULT false
);