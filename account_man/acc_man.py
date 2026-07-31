
def create_user():
    while True:
        username= input("What is the name of the first user \nNote that spaces will be stripped from the password:\n ").strip()

        confirmation = input(f"Can you confirm the username, {username}? [y/n]:")

        if confirmation.lower() != 'y':
            continue
        else:
            break

    while True:
        proposed_pass = input("What is the password you would like to input?\nNote that spaces will be stripped from the password:\n ").strip()
        confirmation = input(f"Can you confirm the password, {proposed_pass}? [y/n]:")
        if confirmation.lower() != 'y':
            continue
        else:
            break


def write_to_db():
    ...
