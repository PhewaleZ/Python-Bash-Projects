# Cybersecurity FastAPI Project

## Core Technologies

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-D71F00?style=for-the-badge&logo=sqlalchemy&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

## Security Intelligence and API Integrations

![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-IP_Reputation-BB2525?style=for-the-badge)
![AlienVault](https://img.shields.io/badge/AlienVault-OTX-orange?style=for-the-badge)
![ipinfo](https://img.shields.io/badge/ipinfo-IP_Geolocation-6366F1?style=for-the-badge)
![Requests](https://img.shields.io/badge/Requests-HTTP_Client-2CA5E0?style=for-the-badge&logo=python&logoColor=white)

## What it is

This project is an API based project written with python using the FastAPI framework.

My software is meant to allow for productivity gains by facilitating the process of conducting rudimentary threat intelligence lookup tasks, by sending an HTTP request to the appropriate endpoint. This project can be deployed onto any machine which has internet connectivity, only authorized users can then proceed to request any potential IOC be scanned and evaluated by pooling data from existing API's such as IPinfo, VirusTotal and Abuselpdb in a clean and formatted output as well as a general assessment based on the received data.

It should be noted that My API only provides an opinion as well as data meant to aid a cybersecurity professional or anyone interested in conducting threat intelligence lookup, best practices should always be followed and an assessment from a single source should not be treated as the be-all and end-all.

Throughout the development of this project, I have been able to advance my knowledge and understanding of the following:

- Backend System Design
- System Design Best Practices
- Data Interpretation and Fusion
- Development of Secure Software
- Git
- Relational Databases (Postgresql)
- Python

## Why I designed it

As part of my journey into the domain of cybersecurity and programming, I learned the importance of threat intelligence and software which can provide meaningful information. I then developed an interest in the development of these software and their role in cybersecurity and as this interest grew my knowledge and interest in API design was also expanding. It didn't take long before I identified a problem:

**How much time is spent constantly accessing and logging into websites such as IPinfo to just specify an Ip address then leave onto the next website?**

In response to this I decided to create a central software which could simplify the tedious process and allow threat intelligence to be conducted from anywhere as long as internet connectivity is provided.

## Directory Structure

Within the top level directory of the project, I have taken on the effort to neatly organize code in an understandable and therefore scalable manner.

### main.py

This is where the main API logic is kept and where the software is ran from.

### pyd_models.py

Within this file, the expected format of the json in the body of the HTTP request is specified.
There is a general format which is present in all:

- username
- key
- target
- optional id
- scan engines to be used

Each endpoint expects a slightly differently named attribute but the general structure is universal.
Measures are already in place to prevent duplicate scanning as well as occurences where no valid scan engine is specified.

### services

This subdirectory contains 4 python files which are used to interact with their respectice tool:

- abuselpdb.py
- alienvault.py
- ipinfoAPI.py
- virustotal.py

### database

This subdirectory contains all database related code such as the database schema and functions which create users as well as the function which returns the hash of a users key when required.

### administrative

This subdirectory contains a 3 important files:

- database_init.py, which is used to automatically create the database and all required tables
- logging.py, which is used to create logs and write them into the database
- user_man.py, which is used to perform administrative tasks such as changing a password, pulling logs related to a user, creating a user or even removing a user

## Endpoint structure

There are 6 endpoints and they all exclusively accept POST requests, their respective paths are:

- /filescans
- /domainscans
- /ipscans
- /urlscans/heavyscans
- /urlscans/lightscans

The names are indicative of their purpose, for further clarification, the "urlscans" endpoint has two nested resources.
"heavyscans" is sends the request to otx.alienvault.com for sandbox analysis and only a link to it is returned, it does not support any other scan engine such as virustotal

"lighscans", this endpoint supports virustotal and alienvault, is much less comprehensive, quicker and returns an actual analysis.

## How to install

The whole software is containerized with docker, simply running the following commands will start the application on your machine along with. If docker is not installed, I recommend following the instructions on the docker website.
The software makes use of Postgresql, so it is also required.

```bash
sudo docker build -t cybersecurity-api
docker run --rm -it --env-file .env cyber-api python database_init.py
```
