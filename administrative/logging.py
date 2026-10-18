from typing import Literal
from database.db_schema import Log
from database.db_functions import record_log

def admin_log(data, detail: Literal["new_user", "password_change", "up_priv", "down_priv", "deleted_user"], subject_name):
    match detail:
        case "new_user":
            log = {"Data": {
                    "Effect": f"New account created with name: {data}",
                    "Done_by": subject_name
                    }}
        case "password_change":
            log = {"Data": {
                "Effect": f"The following user had their password changed: {data}",
                "Done_by": subject_name
            }}
        case "up_priv":
            log = {"Data": {
                "Effect": f"A user has been granted administrative privileges: {data}",
                "Done_by": subject_name
            }}
        case "down_priv":
            log = {"Data": {
                    "Effect": f"A user has lost administrative privileges: {data}",
                    "Done_by": subject_name
            }}
        case "deleted_user":
            log = {"Data": {
                                "Effect": f"A user has been deleted: {data}",
                                "Done_by": subject_name
                        }}
    return log


def create_log(log_type: Literal["administrative", "scan_result"], log_detail: Literal["new_user","password_change", "up_priv", "down_priv", "deleted_user"], data, subject_name: str, subject_id: str, db):
    log_dict = {}
    match log_type:
        case "administrative": 
            log_dict = admin_log(data=data, subject_name=subject_name, detail=log_detail)
        case "scan_result": ... #NOTE : Dont forget to implement this


    log_obj = Log(user_id=subject_id, data=log_dict)
    record_log(db=db, log_obj=log_obj)
    
