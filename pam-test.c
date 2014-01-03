/*
 * Check password changing
 * Copyright (C) 2013 Thorsten Kukuk <kukuk@suse.de>
 * Copyright (C) 2013 Olaf Kirch <okir@suse.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <getopt.h>

static int opt_debug=0;
static int verify_mode=0;
static char *opt_username = "tstpamunix";
static char *opt_password;
static char *opt_old_password = "pamunix0";
static char *opt_new_password = "pAm1uNi%";
static char *opt_pam_service = "passwd";

/* A conversation function which uses an internally-stored value for
   the responses. */
static int
fake_conv (int num_msg, const struct pam_message **msgm,
	   struct pam_response **response, void *appdata_ptr)
{
  struct pam_response *reply;
  int count;

  /* Sanity test. */
  if (num_msg <= 0)
    return PAM_CONV_ERR;

  /* Allocate memory for the responses. */
  reply = calloc (num_msg, sizeof (struct pam_response));
  if (reply == NULL)
    return PAM_CONV_ERR;

  for (count=0; count < num_msg; ++count) {
    char *string=NULL;

    switch (msgm[count]->msg_style) {
    case PAM_PROMPT_ECHO_OFF:
      /* password */
      if (opt_debug)
	fprintf(stderr, " >> Prompt: %s", msgm[count]->msg);
      if (verify_mode)
	string = strdup (opt_password);
      else if ((strcasestr (msgm[count]->msg, "new") != NULL) ||
	       (strcasestr (msgm[count]->msg, "neu") != NULL))
	string = strdup (opt_new_password);
      else
	string = strdup (opt_old_password);
      break;
    case PAM_PROMPT_ECHO_ON:
      /* account */
      if (opt_debug)
	fprintf(stderr, "%s", msgm[count]->msg);
      string = strdup (opt_username);
      break;
    case PAM_ERROR_MSG:
      if (opt_debug)
	fprintf(stderr, "%s\n",msgm[count]->msg);
      break;
    case PAM_TEXT_INFO:
      if (opt_debug)
	fprintf(stdout, "%s\n",msgm[count]->msg);
      break;
    default:
      if (opt_debug)
	fprintf(stderr,"erroneous conversation (%d)\n",
		msgm[count]->msg_style);
      return PAM_CONV_ERR;
    }

    if (string) {                         /* must add to reply array */
      /* add string to list of responses */
      if (opt_debug)
	fprintf(stderr, "\n << Answer: %s\n", string);

      reply[count].resp_retcode = 0;
      reply[count].resp = string;
      string = NULL;
    }
  }

  /* Set the pointers in the response structure and return. */
  *response = reply;
  return PAM_SUCCESS;
}

static struct pam_conv conv = {
    fake_conv,
    NULL
};

/*
 * Helper function for error reporting
 */
static int
report_pam_error(pam_handle_t *pamh, const char *failing_func, int code)
{
  if (pamh != NULL)
    fprintf (stderr, "pam-test: %s returned %d (%s)\n",
		    failing_func, code, pam_strerror(pamh, code));
  else
    fprintf (stderr, "pam-test: %s returned error code %d\n",
		    failing_func, code);
  return 0;
}

static int
test_chauthtok(void)
{
  pam_handle_t *pamh=NULL;
  int retval;

  verify_mode = 0;

  retval = pam_start(opt_pam_service, opt_username, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    return report_pam_error(pamh, "pam_start", retval);

  /* First try it as root, should fail for NIS accounts */
  retval = pam_chauthtok (pamh, 0);
  if (retval != PAM_SUCCESS)
    return report_pam_error(pamh, "pam_chauthtok", retval);

  retval = pam_end (pamh,retval);
  if (retval != PAM_SUCCESS)
    return report_pam_error(NULL, "pam_end", retval);

  opt_password = opt_new_password;

  return 1;
}

static int
test_authenticate(void)
{
  pam_handle_t *pamh=NULL;
  int retval;

  verify_mode = 1;

  retval = pam_start(opt_pam_service, opt_username, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    return report_pam_error(pamh, "pam_start", retval);

  retval = pam_authenticate (pamh, 0);
  if (retval != PAM_SUCCESS)
    return report_pam_error(pamh, "pam_authenticate", retval);

  retval = pam_end (pamh,retval);
  if (retval != PAM_SUCCESS)
    return report_pam_error(NULL, "pam_end", retval);

  return 1;
}

/* Check that errors of optional modules are ignored and that
 * required modules after a sufficient one are not executed.
 */
int
main(int argc, char *argv[])
{
  enum { OPT_DEBUG, OPT_USERNAME, OPT_PASSWORD, OPT_OLD_PASSWORD, OPT_NEW_PASSWORD, OPT_PAM_SERVICE };
  struct option long_options[] = {
	  { "debug",		no_argument,		NULL,	OPT_DEBUG },
	  { "username",		required_argument,	NULL,	OPT_USERNAME },
	  { "password",		required_argument,	NULL,	OPT_PASSWORD },
	  { "old-password",	required_argument,	NULL,	OPT_OLD_PASSWORD },
	  { "new-password",	required_argument,	NULL,	OPT_NEW_PASSWORD },
	  { "pam-service",	required_argument,	NULL,	OPT_PAM_SERVICE },
	  { NULL }
  };
  int c;

  while ((c = getopt_long(argc, argv, "dupON", long_options, NULL)) != EOF) {
    switch (c) {
    case OPT_DEBUG:
      opt_debug++;
      break;

    case OPT_USERNAME:
      opt_username = optarg;
      break;

    case OPT_PASSWORD:
      opt_password = optarg;
      break;

    case OPT_OLD_PASSWORD:
      opt_old_password = optarg;
      break;

    case OPT_NEW_PASSWORD:
      opt_new_password = optarg;
      break;

    case OPT_PAM_SERVICE:
      opt_pam_service = optarg;
      break;

    default:
      fprintf (stderr, "Invalid option, please see source code for documentation\n");
      return 1;
    }
  }

  if (optind >= argc)
    test_authenticate();
  else
    {
      while (optind < argc)
        {
          char *action = argv[optind++];
	  int ok = 0;

	  if (opt_debug)
	    fprintf (stderr, "%s: service=%s user=%s\n", action, opt_pam_service, opt_username);

	  if (!strcmp (action, "authenticate"))
	    ok = test_authenticate();
	  else if (!strcmp (action, "chauthtok"))
	    ok = test_chauthtok();
	  else
	    fprintf (stderr, "unsupported action \"%s\"\n", action);

	  if (!ok)
	    {
	      fprintf (stderr, "%s: verification failed\n", action);
	      return 1;
	    }

	  printf("%s: success\n", action);
	}
    }

  printf ("All verifications completed successfully\n");
  return 0;
}
