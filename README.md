# Secure File Manager MVP

MVP защищенного веб-сервиса на FastAPI для безопасного хранения файлов.

## Стек технологий
* FastAPI
* Pydantic v2
* Cryptography (Fernet)
* Docker & Docker Compose

## Тесты 
``` python test_client.py ```

## Инструкция по развертыванию
1. Клонирование репозитория: ```bash git clone ```
2. Создание виртуального окружения venv ``` python3 -m venv venv ```
3. Активация venv ``` source venv/bin/activate ```
4. Установка всех зависимостей ``` pip install --upgrade pip, pip install -r requirements.txt ```
5. Настройка env ``` cp .env.example .env  ```
6. Запуск сервера ``` uvicorn main:app --reload --host 127.0.0.1 --port 8000 ```

## Вариант с Docker
1. Настройка env ``` cp .env.example .env  ```
2. Запуск контейнера ``` docker-compose up --build -d ```

## Как перейти на сайт
[text](http://127.0.0.1:8000/docs)