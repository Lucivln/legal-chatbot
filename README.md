# 🧑‍⚖️ Legal Chatbot for Indian Law (AI-powered)

An AI-powered Legal Chatbot built using Flask, MySQL, and a custom locally-run model (`indian-law-llama`) via Ollama. This chatbot can answer Indian legal queries, recommend legal content, allow admin-controlled case additions, and support secure user access with RBAC (Role-Based Access Control).

---

## 🔥 Features

- 🔐 User Authentication with Email and Password
- 🛡️ Role-Based Access Control (Admin/User)
- 💬 AI Chat Interface for Legal Queries
- 📚 Landmark Case Search and Recommendations
- 🧠 Locally Running Ollama AI Model Integration
- 📝 Feedback Storage in MySQL
- 📈 Admin Dashboard for Managing Cases

---

## 📸 Screenshots

> ![WhatsApp Image 2025-04-16 at 12 08 10_1624d9b0](https://github.com/user-attachments/assets/b828d73f-46b7-4781-9bef-93ef2bcb06fc)

> ![image](https://github.com/user-attachments/assets/a200981c-190c-4397-b0d1-b741050bbfff)

> ![WhatsApp Image 2025-04-16 at 12 13 16_79490a3b](https://github.com/user-attachments/assets/8351559d-dec3-4191-ab2e-1c4957afaa29)

> ![WhatsApp Image 2025-04-16 at 12 13 36_2ea1dad6](https://github.com/user-attachments/assets/eff579c2-1443-446e-984c-703d488280fa)

> ![WhatsApp Image 2025-04-16 at 12 14 05_5ac3f8a5](https://github.com/user-attachments/assets/7cc90a25-61d6-430b-bd57-cff291b866a3)



---



## ⚙️ Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript
- **Backend**: Python (Flask)
- **Database**: MySQL
- **AI Model**: `indian-law-llama` via Ollama
- **Authentication**: SQL-based, hashed passwords
- **Architecture**: Microservices-based

---

## 🚀 Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/your-username/legal-chatbot.git
cd legal-chatbot
```

### ✅ Prerequisites
Before you begin, make sure the following are installed on your system:

### 🔧 System Requirements
Python 3.8+

MySQL Server (5.7+ or 8.x)

Ollama (for running the indian-law-llama AI model locally)

Git

### 📦 Python Libraries (auto-installed via requirements.txt)
Flask

Flask-MySQL

Flask-Login

Flask-WTF

Werkzeug

bcrypt

python-dotenv

openai (if applicable)

requests

Install all dependencies using:
```
pip install -r requirements.txt
```
### 🐬 MySQL Setup
Ensure MySQL is running.

Create a database, e.g., legal_chatbot_db.

### 🧠 Ollama Setup (AI Model)
Install Ollama: (https://ollama.com/download)
Start Ollama:

```
ollama run indian-law-llama
```
### 3. Setup MySQL Database
Use the following sql commands for the required database tables.
```
-- Drop existing tables if needed
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS feedback;
DROP TABLE IF EXISTS case_laws;

-- Users Table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Roles Table
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE
);

-- User Roles (Many-to-Many Relationship)
CREATE TABLE user_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Password Reset Table
CREATE TABLE password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    reset_token VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Feedback Table
CREATE TABLE feedback (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    message TEXT NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Landmark Legal Cases Table
CREATE TABLE case_laws (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_name VARCHAR(255) NOT NULL,
    case_type VARCHAR(100),
    case_date DATE,
    summary TEXT,
    full_text TEXT,
    added_by INT,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Default Roles (insert on first migration)
INSERT INTO roles (role_name) VALUES ('admin'), ('user');
```
Update your MySQL credentials in app/app.py

### 4. Run AI Model (Ollama)
```
ollama run indian-law-llama
```
### 5. Start the Flask Server
```
python app/app.py
```

## 🧪 Tests
Coming soon: Unit tests for route and model validation.

## 🛡️ License
This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙌 Acknowledgements

- [**Ollama**](https://ollama.com/) – for providing a framework to run and manage local AI models efficiently.
- [**OpenAI ChatGPT**](https://openai.com/chatgpt) – for architectural guidance, development brainstorming, and best practice insights.
- [**Indian Kanoon**](https://indiankanoon.org/) – for reference to Indian laws, cases, and legal corpus.
- [**Bare Acts Live**](https://www.bareactslive.com/) – for access to various Indian statutes and acts.
- [**Vakilno1**](https://www.vakilno1.com/) – for practical legal articles and simplified explanations of Indian law.
- [**Legitquest**](https://www.legitquest.com/) – for legal research and landmark judgments database.
