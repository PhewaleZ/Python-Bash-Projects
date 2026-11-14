from typing import Literal
from database.db_schema import Log
from database.db_functions import record_log, retrieve_all_logs,retrieve_user_logs

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

def scan_log(subject_name: str, scan_result: dict):
    log = {"Data": {
        "Effect": f"A scan has been done",
        "Done_by": subject_name,
        "Scan_data": scan_result
                }}

    return log

def create_log(log_type: Literal["administrative", "scan_result"], log_detail: Literal["new_user","password_change", "up_priv", "down_priv", "deleted_user", "standard_scan"], subject_name: str, subject_id: str, db,scan_result = [], admin_data = ""):
    log_dict = {}
    match log_type:
        case "administrative": 
            assert log_detail != "standard_scan"
            log = admin_log(data=admin_data, subject_name=subject_name, detail=log_detail) 
        case "scan_result":
            assert log_detail == "standard_scan"
            log = scan_log( subject_name=subject_name, scan_result=scan_result)

    log_obj = Log(user_id=subject_id, data=log)
    record_log(db=db, log_obj=log_obj)
    
def export_logs(db,retrieve_all: bool,target_userid=""):

    if retrieve_all is True:
        all_logs = retrieve_all_logs(db=db)

    else:
        all_logs = retrieve_user_logs(db=db, target_userid=target_userid)

    all_logs = [
    {
        "log_detail": row["data"],
        "created_at": row["timestamp"].isoformat(),
        "log_subjectid": str(row["user_id"]),
        "log_id": str(row["log_id"])
    }
    for row in all_logs
]
    return all_logs
    