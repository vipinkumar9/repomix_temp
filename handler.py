# Handler for AWS Lambda
import json
import os
import traceback

import requests
import serverless_wsgi
from autodidact.wsgi import application
from aws_lambda_powertools import Logger
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session

from core.models import User
from core.utils import get_claims

logger = Logger()

user_permissions_query = """
    query userPermissions($email:String!, $tenantId:String!, $productName:String!){
        getUserPermissions(email:$email, tenantId:$tenantId, productName:$productName){
            permissions
        }
    }
"""


def get_user_from_session(event, tool_name):
    session_id = "_sessionid="
    session_tenant_id = "session_tenant="
    logger.info(
        "List of available cookies",
        extra={"cookies": event.get("headers").get("cookie"), "tool_name": tool_name},
    )
    try:
        session_id_slice_id = (
            event.get("headers").get("cookie", "").find(str(tool_name) + session_id)
        )
        logger.info(f"session_id_slice_id: {session_id_slice_id}")
        if session_id_slice_id == -1:
            raise ValueError("session_id_slice_id not present")
        cookie_value = "cookie"
    except Exception as e:
        logger.exception(e)
        session_id_slice_id = event.get("headers")["Cookie"].find(
            str(tool_name) + session_id
        )
        cookie_value = "Cookie"

    slice_start = session_id_slice_id + len(tool_name) + len(session_id)
    session_key = event.get("headers")[cookie_value][slice_start:].split(";")[0]
    try:
        session = Session.objects.get(session_key=session_key)
        uid = session.get_decoded().get("_auth_user_id")
        user = User.objects.get(uuid=uid)

        logger.info(user)
        # fetch session tenant
        if event.get("headers")[cookie_value].find(session_tenant_id) == -1:
            session = SessionStore(session_key=session_key)
            session.flush()
        else:
            session_tenant_slice_id = event.get("headers")[cookie_value].find(
                session_tenant_id
            )
            session_tenant_slice_start = session_tenant_slice_id + len(
                session_tenant_id
            )
            session_tenant = event.get("headers")[cookie_value][
                session_tenant_slice_start:
            ].split(";")[0]
            if session_tenant is None:
                session = SessionStore(session_key=session_key)
                session.flush()
    except Session.DoesNotExist:
        logger.exception(f"Session does not exist")
    except Exception as e:
        logger.exception(f"error while getting session: {e}")

    return user


def get_access_token(token_url, client_id, client_secret):
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    response = requests.post(token_url, data=data)
    return response.json()["access_token"]


def handler(event, context):  # NOSONAR #needed for multiple notifications
    logger.info(f"Handler Event: {event}")
    response = None
    try:
        logger.info("Setting origin")
        os.environ["ORIGIN"] = event.get("headers").get(
            "origin", event.get("headers").get("Origin", "null")
        )
    except Exception as e:
        logger.exception(str(e))
        os.environ["ORIGIN"] = "null"
    try:
        headers = {
            "x-api-token": get_access_token(
                settings.COGNITO_TOKEN_URI,
                settings.B2B_CLIENT_ID,
                settings.B2B_CLIENT_SECRET,
            )
        }

        tool_name = settings.TOOL_NAME
        session_tenant = None
        user_email = None
        try:
            token = event.get("headers").get("x-api-token")
            logger.info(
                "Trying to fetch user details from x-api-token",
                extra={"x-api-token": token, "headers": event.get("headers")},
            )
            if token:
                claims = get_claims(token)
                logger.debug(f"claims: {claims}")
                user_email = claims.get("email")
                session_tenant = claims.get("session_tenant")

            logger.info(user_email)
            mutation_variables = {
                "email": user_email
                or event.get("requestContext", {})
                .get("authorizer", {})
                .get("claims", {})
                .get("email", None),
                "tenantId": session_tenant
                or event.get("requestContext", {})
                .get("authorizer", {})
                .get("claims", {})
                .get("session_tenant", None),
                "productName": tool_name,
            }
        except Exception as e:
            logger.exception(e)
            logger.info("Trying to fetch user details from session")
            user = get_user_from_session(event, tool_name)
            logger.info(user)
            mutation_variables = {
                "email": user.email,
                "tenantId": session_tenant,
                "productName": tool_name,
            }
        logger.info(mutation_variables)
        response = requests.post(
            settings.CAM_B2B_ENDPOINT,
            json={"query": user_permissions_query, "variables": mutation_variables},
            headers=headers,
        )

        logger.info(response.status_code)
        if response.status_code == 200:
            res = (
                response.json()
                .get("data", {})
                .get("getUserPermissions", {})
                .get("permissions", {})
                .get(tool_name)
            )
            event["requestContext"]["user-permission"] = json.dumps(res)
            logger.info("fetched CAM permissions successfully")
        else:
            logger.error("Response failed from CAM Permission")

    except Exception as e:
        logger.info(
            f"resp cam from handler failed: {response.json() if response else None}"
        )
        logger.exception(f"cam handler error {e}")

    if "django_command" in event:
        return execute(
            event["django_command"],
            event.get("django_command_args", []),
            event.get("django_command_options", {}),
        )
    if "send_email_to_employee_after_course_deadline" in event:
        from autodidact.email.self_learning.schedule_email_for_employee import (
            send_email_to_employee_after_course_deadline,
        )
        from status_tracker.tracker import Tracker

        try:
            logger.info(
                "Calling send_email_to_employee_after_course_deadline from Handler"
            )
            send_email_to_employee_after_course_deadline()
            logger.info(
                "Calling Tracker from Handler inside send_email_to_employee_after_course_deadline"
            )
            return Tracker.track()
        except Exception as e:
            logger.exception(
                f"Exception in send_email_to_employee_after_course_deadline: {e}"
            )
            traceback.print_exc()
            return None

    if (
        "track_user_course_relation_status" in event
    ):  # We were not using Tracker as of now in scheduler. Adding it with course_deadline schedule
        from status_tracker.tracker import Tracker

        try:
            logger.info(
                "Calling Tracker from Handler for condition track_user_course_relation_status"
            )
            return Tracker.track()
        except Exception as e:
            logger.exception(f"Exception while handler call for autodidact api. {e}")
            traceback.print_exc()
            return None

    if "create_super_user" in event:
        from super_user.super_user import create_super_user

        try:
            logger.info("Calling create_super_user from Handler")
            return create_super_user()
        except Exception as e:
            logger.exception(f"Exception while create super user. {e}")
            traceback.print_exc()
            return None

    if "archive_master_repo" in event:
        from status_tracker.archive import ArchiveMasterRepo

        try:
            logger.info("Calling ArchiveMasterRepo from Handler")
            return ArchiveMasterRepo.archive()
        except Exception as e:
            logger.exception(f"Exception while calling handler for autodidact api. {e}")
            return None

    if "delete_user_and_schema" in event:
        from post_assessment.drop_user_and_schema import delete_user_and_schema

        try:
            logger.info("Calling delete_user_and_schema from Handler")
            return delete_user_and_schema()
        except Exception as e:
            logger.exception(f"Exception while deleting user and schema. {e}")
            traceback.print_exc()
            return None

    if "dashboard_users_name_cleanup" in event:
        from core.graphql.user.dashboard_users_name_cleanup import (
            dashboard_users_name_cleanup,
        )

        try:
            logger.info("Calling dashboard_users_name_cleanup from Handler")
            return dashboard_users_name_cleanup()
        except Exception as e:
            logger.exception(f"Exception while correcting dashboard users name: {e}")
            traceback.print_exc()
            return None

    if "send_notification_for_auto_submit" in event:
        from notification_auto_submit.auto_submit_notification import (
            send_notification_for_auto_submit,
        )

        try:
            logger.info("Calling send_notification_for_auto_submit from Handler")
            return send_notification_for_auto_submit()
        except Exception as e:
            logger.exception(
                f"Exception while sending notification for auto submit to track lead: {e}"
            )
            traceback.print_exc()
            return None

    if "trigger_all_lambdas" in event:
        from trigger_lambdas.trigger_lambdas import trigger_lambdas

        try:
            logger.info("Calling trigger_lambdas from Handler")
            return trigger_lambdas()
        except Exception as e:
            logger.exception(f"Exception while invoking lambdas: {e}")
            traceback.print_exc()
            return None

    if "send_email_about_quiz_availability" in event:
        from schedule_email_to_trainees.schedule_email import (
            send_email_about_quiz_availability,
        )

        try:
            logger.info("Calling send_email_about_quiz_availability from Handler")
            return send_email_about_quiz_availability()
        except Exception as e:
            logger.exception(
                f"Exception while sending email about quiz availability: {e}"
            )
            traceback.print_exc()
            return None

    if "send_email_to_director_and_tracklead" in event:
        from schedule_email_to_TL_HUD_Admin.schedule_email_to_admins import (
            send_email_to_director_and_tracklead,
        )

        try:
            logger.info("Calling send_email_to_director_and_tracklead from Handler")
            return send_email_to_director_and_tracklead()
        except Exception as e:
            logger.exception(f"Exception while sending email to HUD and TL: {e}")
            traceback.print_exc()
            return None

    if "send_email_to_cumulus_self_learning_admin" in event:
        from schedule_email_to_TL_HUD_Admin.schedule_email_to_admins import (
            send_email_to_cumulus_self_learning_admin,
        )

        try:
            logger.info(
                "Calling send_email_to_cumulus_self_learning_admin from Handler"
            )
            return send_email_to_cumulus_self_learning_admin()
        except Exception as e:
            logger.exception(
                f"Exception while sending email to Cumulus self learning admin: {e}"
            )
            traceback.print_exc()
            return None

    if "train_ai_assistant_with_data" in event:
        from ai_assistant.scheduler_event.train_ai_assistant_with_data import (
            train_ai_assistant_with_data,
        )

        try:
            logger.info("Calling train_ai_assistant_with_data from Handler")
            return train_ai_assistant_with_data()
        except Exception as e:
            logger.exception(f"Exception while training ai assistant with data: {e}")
            traceback.print_exc()
            return None

    if "send_email_to_employee_before_course_deadline" in event:
        from autodidact.email.self_learning.schedule_email_for_employee import (
            send_email_to_employee_before_course_deadline,
        )

        try:
            logger.info(
                "Calling send_email_to_employee_before_course_deadline from Handler"
            )
            return send_email_to_employee_before_course_deadline()
        except Exception as e:
            logger.exception(
                f"Exception in send_email_to_employee_before_course_deadline: {e}"
            )
            traceback.print_exc()
            return None

    if "reminder_to_create_evaluation_sheet" in event:
        from autodidact.email.email_utils import reminder_to_create_evaluation_sheet

        try:
            logger.info("Calling reminder_to_create_evaluation_sheet from Handler")
            return reminder_to_create_evaluation_sheet()
        except Exception as e:
            logger.exception(f"Exception in reminder_to_create_evaluation_sheet: {e}")
            traceback.print_exc()
            return None

    if "reminder_to_publish_evaluation_results" in event:
        from autodidact.email.email_utils import reminder_to_publish_evaluation_results

        try:
            logger.info("Calling reminder_to_publish_evaluation_results from Handler")
            return reminder_to_publish_evaluation_results()
        except Exception as e:
            logger.exception(
                f"Exception in reminder_to_publish_evaluation_results: {e}"
            )
            traceback.print_exc()
            return None

    if "user_course_relation_enrollment_fix" in event:
        try:
            logger.info("Calling run_user_course_relation_enrollment_fix from Handler")
            from prod_fix_scripts.user_course_relation_enrollment_fix import (
                run_user_course_relation_enrollment_fix,
            )

            return run_user_course_relation_enrollment_fix()
        except Exception as e:
            logger.exception(f"Exception while handler call for autodidact api. {e}")
            traceback.print_exc()
            return None

    if "delete_sonarqube_reports" in event:
        try:
            logger.info("Calling delete_sonarqube_reports from Handler")
            from status_tracker.tracker import delete_sonarqube_reports

            return delete_sonarqube_reports()
        except Exception as e:
            logger.exception(f"Exception while handler call for autodidact api. {e}")
            traceback.print_exc()
            return None

    if "feature_flag_fix" in event:
        try:
            logger.info("Calling feature_flag_fix from Handler")
            from prod_fix_scripts.feature_flag_fix import add_feature_flags

            return add_feature_flags()
        except Exception as e:
            logger.exception(f"Exception while handler call for autodidact api. {e}")
            traceback.print_exc()
            return None

    if "mark_pending_course_of_self_learning" in event:
        try:
            from autodidact.email.self_learning.schedule_email_for_employee import (
                send_email_to_employee_after_course_deadline,
            )
            from status_tracker.self_learning_scheduler import SelfLearningScheduler

            logger.info("Calling mark_pending_course_of_self_learning")
            send_email_to_employee_after_course_deadline()
            self_learning = SelfLearningScheduler()
            return self_learning.run()

        except Exception as e:
            logger.exception(f"Exception in mark_pending_course_of_self_learning: {e}")
            traceback.print_exc()
            return None

    if "mark_pending_course_of_bootcamp" in event:
        try:
            from status_tracker.bootcamp_scheduler import BootcampScheduler

            logger.info("Calling mark_pending_course_of_bootcamp")
            bootcamp_scheduler = BootcampScheduler()
            return bootcamp_scheduler.run()

        except Exception as e:
            logger.exception(f"Exception in mark_pending_course_of_self_learning: {e}")
            traceback.print_exc()
            return None

    if "end_enrollment_if_failed_self_learning" in event:
        try:
            from status_tracker.end_enrollments_scheduler import EndEnrollmentScheduler

            logger.info("Calling end_enrollment_if_failed_self_learning")
            enrollment_scheduler = EndEnrollmentScheduler()
            return enrollment_scheduler.run()

        except Exception as e:
            logger.exception(
                f"Exception in end_enrollment_if_failed_self_learning: {e}"
            )
            traceback.print_exc()
            return None

    if "send_email_to_participants_after_track_ends" in event:
        from schedule_email_to_trainees.schedule_email import (
            send_email_to_participants_after_track_ends,
        )
        from status_tracker.bootcamp_scheduler import BootcampScheduler

        try:
            logger.info(
                "Calling send_email_to_participants_after_track_ends from Handler"
            )
            send_email_to_participants_after_track_ends()
            logger.info(
                "Calling Tracker from Handler inside send_email_to_participants_after_track_ends"
            )
            bootcamp_scheduler = BootcampScheduler()
            return bootcamp_scheduler.run()
        except Exception as e:
            logger.exception(
                f"Exception in send_email_to_participants_after_track_ends: {e}"
            )
            traceback.print_exc()
            return None

    if "send_email_to_participants_for_reminder_to_complete_the_milestones" in event:
        from schedule_email_to_trainees.schedule_email import (
            send_email_to_participants_for_reminder_to_complete_the_milestones,
        )
        from status_tracker.bootcamp_scheduler import BootcampScheduler

        try:
            logger.info(
                "Calling send_email_to_participants_for_reminder_to_complete_the_milestones from Handler"
            )
            send_email_to_participants_for_reminder_to_complete_the_milestones()
            logger.info(
                "Calling Tracker from Handler inside send_email_to_participants_for_reminder_to_complete_the_milestones"
            )
            bootcamp_scheduler = BootcampScheduler()
            return bootcamp_scheduler.run()
        except Exception as e:
            logger.exception(
                f"Exception in send_email_to_participants_for_reminder_to_complete_the_milestones: {e}"
            )
            traceback.print_exc()
            return None

    if "send_evaluation_reminder_to_track_evaluators" in event:
        from schedule_email_to_trainees.schedule_email import (
            send_evaluation_reminder_to_track_evaluators,
        )
        from status_tracker.bootcamp_scheduler import BootcampScheduler

        try:
            logger.info(
                "Calling send_evaluation_reminder_to_track_evaluators from Handler"
            )
            send_evaluation_reminder_to_track_evaluators()
            logger.info(
                "Calling Tracker from Handler inside send_evaluation_reminder_to_track_evaluators"
            )
            bootcamp_scheduler = BootcampScheduler()
            return bootcamp_scheduler.run()
        except Exception as e:
            logger.exception(
                f"Exception in send_evaluation_reminder_to_track_evaluators: {e}"
            )
            traceback.print_exc()
            return None

    return serverless_wsgi.handle_request(application, event, context)


def execute(cmd, args={}, options={}):
    from django.core import management

    management.call_command(cmd, *args, **options)


if __name__ == "__main__":
    execute("migrate")
