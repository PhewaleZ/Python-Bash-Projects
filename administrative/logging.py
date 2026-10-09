from typing import Literal

def admin_log(data, detail: Literal["new_user", "password_change", "up_priv", "down_priv"], subject):
    match detail:
        case "new_user":
            log = {"Data": {
                    "Effect": f"New account created with name: {detail}",
                    "Done_by": subject
                    }}
        case "password_change":
            log = {"Data": {
                "Effect": f"The following user had their password changed: {detail}",
                "Done_by": subject
            }}
        case "up_priv":
            log = {"Data": {
                "Effect": f"A user has been granted administrative privileges: {detail}",
                "Done_by": subject
            }}
        case "down_priv":
            log = {"Data": {
                    "Effect": f"A user has lost administrative privileges: {detail}",
                    "Done_by": subject
            }}
        


def main(log_type: Literal["administrative", "scan_result"], data):
    ...
