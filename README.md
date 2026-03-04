# AppSec Notes API

A simple FastAPI application used for learning application security concepts.

## Features

- User registration
- JWT authentication
- Role-based access
- Notes API
- Admin endpoint

## Learning Goals

This project intentionally introduces security flaws that can later be fixed.

Topics explored:
- Authentication mistakes
- Authorization bugs
- IDOR vulnerabilities
- Secure coding practices

## Run Locally

Install dependencies:

pip install -r requirements.txt

Run server:

uvicorn main:app --reload
