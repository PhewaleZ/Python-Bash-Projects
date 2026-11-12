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

**How much time is spent constantly accessing and logging into websites such as IPinfo to just specify an IP address then leave onto the next website?**

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

There are 6 endpoints, which all follow RESTful API design guidelines.

All 6 exclusively accept POST requests, their respective paths are:

- /filescans
- /domainscans
- /ipscans
- /urlscans/heavyscans
- /urlscans/lightscans

The names are indicative of their purpose, for further clarification, the "urlscans" endpoint has two nested resources.
"heavyscans" is sends the request to otx.alienvault.com for sandbox analysis and only a link to it is returned, it does not support any other scan engine such as virustotal

"lighscans", this endpoint supports virustotal and alienvault, is much less comprehensive, quicker and returns an actual analysis.

## Security Features

Security measures should be implemented at all relevant layers, not just at the physical device itself. To adhere to this general guideline, I have taken several decisions to help bolster the security of the software such as:

- Logging is implemented
- Secure .env file handling
- Password enumeration mitigation techniques
- multilayered security
- Storing keys as hashes
- masked input fields for password input

A threat may attempt to acquire information on whether or not a specific user is in the database, to help combat this, if a username does not exist, a "dummy" password is hashed and passed into bcrypt.

![Dummy-password-implementation](./screenshots/dummy%20password.png)

This feature is also implemented in the user_man.py file.

In the database, a user's respective key is stored as a hash, never plaintext. If the keys in the database are ever leaked attackers wont be able to easily decrypt the them, this would make the information less useful and minimize any impact to security.

There are various other measures which help increase security throughout the software's code.

## Database

The data to be stored in the database was relational as the ID's of users had to match an entry in the table of logs, because of this, a relational database is the prefered. This lead to me selected Postgresql due to my existing familiarity and its open source nature.
For more information on the tables refer to the "db_schema.py" file in the "services" subdirectory.

More information on the two tables I have used is below.

### Users

This database table can be demonstrated with the following:

| Column name | Data type | Example | Column Purpose |
| --- | --- | --- | --- |
| username | string | Alex_Donald | This stores the username |
| User_id (Primary Key) | UUID7 | 01809424-3e59-7c05-9219-566f82fff672 | This stores the unique ID of a user |
| user_key | string | $2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW | This holds the hash of the users password using bcrypt's Blowfish Cipher |
| is_admin | boolean | False | This is used to determine if that specific user has administrative authorization |

![Users-table](./screenshots/users%20table.png)

### Logs

This database table holds logs relating to scans conducted by users or general administrative actions

| Column name | Data type | Example | Column Purpose |
| --- | --- | --- | --- |
| user_id | uuid7 | 01809424-3e59-7c05-9219-566f82fff672 | This references the primary key of a user in the users table |
| timestamp | datetime (From sqlalchemy) | YYYY-MM-DD HH24:MI:SS | This holds the time that the log was recorded |
| data | JSON (string) | General JSON file highlighting the action and subject | This column stores the details of the action that occured |
| log_id | uuid7 | 18909424-4d34-7805-9219-aggf82fff672 | this holds the unique ID of that log |

![Log-data-example](./screenshots/example%20of%20log%20data.png)

The image above is an example of the a log entry in the logs table after being extracted by a function through the user_man.py file.

The keys are modified when logs are extracted for clarity reasons.

![Log-table](./screenshots/logs%20table.png)

## How to install

The whole software is containerized with docker, simply running the following commands will start the application on your machine along with. If docker is not installed, I recommend following the instructions on the docker website.
The software makes use of Postgresql, so it is also required.

```bash
sudo docker build -t cybersecurity-api .
docker run --rm -it --env-file .env cybersecurity-api python database_init.py
```

## Lessons Learned

Throughout the months I have spent creating this software I encountered various problems, each were an opportunity to learn something new.

### Type Safety

In the earlier iterations of the application, I frequently ignored pylance messages informing me that a variable may be unbound or a function may not return the specified variable type in all possible paths. I used this project as an opportunity to better understand static type checking and how to better utilize pylance to minimize logical errors in code where a variable doesn't belong to the anticipated type therefore catching errors before the code is run.

### Exception Handling

At the beginning, I struggled to code an appropriate flow of try/except blocks for handling instances where an HTTP request to an external API did not return a 200 status code. This gave me the chance to improve my understanding of try/except blocks as well as how to utilize "else" and "finally". I also had to learn more about the types of errors relating to the requests module and HTTP in general. I learned about 4xx status code class, their definition, when they are returned etc.

### GitHub

An important part of the project was github, and as a result, my confidence and comfortability conducting a range of everyday github commands did improve.

Examples of commands I commonly used:

- git add
- git commit
- git log
- git branch
- git merge

### Modular Programming

Ensuring that functions from multiple seperate files and in seperate directories proved to be a new learning opportunity as prior to this project I had only conducted a modular programming on a smaller scale. Creating reusable functions and easy to debug as well as maintain modules, helped me better understand how to write code capable of integrating well with external software and other pieces of code internally.

### Docker

NOTE: Add this last after the application is fully containerized and easy to run

## Potential Improvements

### Async Functions

To help provide more stable server-side responses if the scale of the project increases, Incorporating asynchronus functions will allow other tasks and requests to be processed as the software awaits the result of a scan from an external API. This would allow for better and mroe efficient usage of computing resources and allow the software to better accomodate a large number of users.

### User Interface

Instead of having users conduct a post request with the linux command curl or any other alternative, providing a us interface whether CLI or GUI, would allow less tech-savvy to better understand how to make use of the software. Making the software more accessible results in a shallower learning curve, allowing individuals to quickly make use of the software without the need for complex explanations or training.
