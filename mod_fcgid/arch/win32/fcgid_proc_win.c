#include "httpd.h"
#include "arch/win32/apr_arch_file_io.h"
#include "apr_thread_proc.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "util_script.h"
#include "mod_core.h"
#include "mod_cgi.h"
#include "apr_tables.h"
#include "fcgid_proc.h"
#include "fcgid_proctbl.h"
#include "fcgid_protocol.h"
#include "fcgid_conf.h"
#include "fcgid_pm.h"
#include "fcgid_spawn_ctl.h"
#define SHUTDOWN_EVENT_NAME "_FCGI_SHUTDOWN_EVENT_"
#define CONTENT_LENGTH_NAME "CONTENT_LENGTH"
#define FINISH_EVENT_DATA_NAME "finish_event"

/* It's tested on WinNT ONLY, if it work on the other MS platform, let me know */
#if WINVER < 0x0400
#error It is tested on WinNT only
#endif

typedef struct
{
  HANDLE handle_pipe;
  OVERLAPPED overlap_read;
  OVERLAPPED overlap_write;
}
fcgid_namedpipe_handle;

static int g_process_counter = 0;
static apr_pool_t *g_inode_cginame_map = NULL;

static apr_status_t
close_finish_event (void *finishevent)
{
  HANDLE *finish_event = finishevent;
  CloseHandle (*finish_event);
  return APR_SUCCESS;
}

apr_status_t
proc_spawn_process (fcgid_proc_info * procinfo, fcgid_procnode * procnode)
{
  HANDLE *finish_event, listen_handle;
  int bufused = 0;
  SECURITY_ATTRIBUTES SecurityAttributes;
  apr_procattr_t *proc_attr;
  apr_status_t rv;
  const char **argv = NULL;
  apr_file_t *file;
  char **proc_environ;
  char key_name[_POSIX_PATH_MAX];
  char sock_path[_POSIX_PATH_MAX];
  char *dummy;
  memset (&SecurityAttributes, 0, sizeof (SecurityAttributes));

  /* Create the pool if necessary */
  if (!g_inode_cginame_map)
    apr_pool_create (&g_inode_cginame_map,
		     procinfo->main_server->process->pconf);
  if (!g_inode_cginame_map)
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    procinfo->main_server,
		    "mod_fcgid: can't cgi name map table");
      return APR_ENOMEM;
    }

  /* Prepare finish event */
  finish_event = apr_palloc (procnode->proc_pool, sizeof (HANDLE));
  if (!finish_event)
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    procinfo->main_server,
		    "mod_fcgid: can't allocate finish event");
      return APR_ENOMEM;
    }
  *finish_event = CreateEvent (NULL, TRUE, FALSE, NULL);
  if (*finish_event == NULL
      || !SetHandleInformation (*finish_event, HANDLE_FLAG_INHERIT, TRUE))
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    procinfo->main_server,
		    "mod_fcgid: can't create mutex for subprocess");
      return APR_ENOLOCK;
    }
  apr_pool_cleanup_register (procnode->proc_pool, finish_event,
			     close_finish_event, apr_pool_cleanup_null);

  /* For proc_kill_gracefully() */
  apr_pool_userdata_set (finish_event, FINISH_EVENT_DATA_NAME,
			 NULL, procnode->proc_pool);

  /* Pass the finish event id to subprocess */
  apr_table_setn (procinfo->proc_environ, SHUTDOWN_EVENT_NAME,
		  apr_ltoa (procnode->proc_pool, (long) *finish_event));
  /* Set CONTENT_LENGTH_NAME make fastcgi server not block on stdin */
  apr_table_setn (procinfo->proc_environ, CONTENT_LENGTH_NAME, "1");

  /* Prepare the listen namedpipe file name */
  apr_snprintf (sock_path, _POSIX_PATH_MAX - 1,
		"\\\\.\\pipe\\fcgidpipe-%u.%lu",
		GetCurrentProcessId (), g_process_counter++);

  /* Prepare the listen namedpipe handle */
  SecurityAttributes.bInheritHandle = TRUE;
  SecurityAttributes.nLength = sizeof (SecurityAttributes);
  SecurityAttributes.lpSecurityDescriptor = NULL;
  listen_handle = CreateNamedPipe (sock_path,
				   PIPE_ACCESS_DUPLEX,
				   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
				   PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 8192,
				   8192, 0, &SecurityAttributes);
  if (listen_handle == INVALID_HANDLE_VALUE)
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    procinfo->main_server,
		    "mod_fcgid: can't create namedpipe for subprocess");
      return APR_ENOSOCKET;
    }
  strncpy (procnode->socket_path, sock_path, _POSIX_PATH_MAX - 1);
  procnode->socket_path[_POSIX_PATH_MAX - 1] = '\0';

  /* Build environment variables */
  proc_environ = ap_create_environment (procnode->proc_pool,
					procinfo->proc_environ);
  if (!proc_environ)
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    procinfo->main_server,
		    "mod_fcgid: can't build environment variables");
      return APR_ENOMEM;
    }

  /* Create process now */
  if (!
      (procnode->proc_id =
       apr_pcalloc (procnode->proc_pool, sizeof (apr_proc_t)))
      || (rv =
	  apr_procattr_create (&proc_attr,
			       procnode->proc_pool)) != APR_SUCCESS
      || (rv =
	  apr_procattr_dir_set (proc_attr,
				ap_make_dirstr_parent (procnode->proc_pool,
						       procinfo->cgipath))) !=
      APR_SUCCESS
      || (rv =
	  apr_procattr_cmdtype_set (proc_attr, APR_PROGRAM)) != APR_SUCCESS
      || (rv = apr_procattr_detach_set (proc_attr, 1)) != APR_SUCCESS
      || (rv =
	  apr_os_file_put (&file, &listen_handle, 0,
			   procnode->proc_pool)) != APR_SUCCESS
      || (rv =
	  apr_procattr_child_in_set (proc_attr, file, NULL)) != APR_SUCCESS
      || (rv =
	  apr_proc_create (procnode->proc_id, procinfo->cgipath, NULL,
			   proc_environ, proc_attr,
			   procnode->proc_pool)) != APR_SUCCESS)
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, rv, procinfo->main_server,
		    "mod_fcgid: can't create fastcgi process");
      CloseHandle (listen_handle);
      return APR_ENOPROC;
    }

  /* OK, I created the process, now put it back to idle list */
  CloseHandle (listen_handle);

  /* Set the (deviceid, inode) -> fastcgi path map for log */
  apr_snprintf (key_name, _POSIX_PATH_MAX, "%lX%lX",
		procnode->inode, procnode->deviceid);
  dummy = NULL;
  apr_pool_userdata_get (&dummy, key_name, g_inode_cginame_map);
  if (!dummy)
    {
      /* Insert a new item if key not found */
      char *put_key = apr_psprintf (g_inode_cginame_map, "%lX%lX",
				    procnode->inode, procnode->deviceid);
      char *fcgipath = apr_psprintf (g_inode_cginame_map, "%s",
				     procinfo->cgipath);
      if (put_key && fcgipath)
	apr_pool_userdata_set (fcgipath, put_key, NULL, g_inode_cginame_map);
    }

  return APR_SUCCESS;
}

apr_status_t
proc_kill_gracefully (fcgid_procnode * procnode, server_rec * main_server)
{
  HANDLE *finish_event = NULL;

  apr_pool_userdata_get ((void **) &finish_event,
			 FINISH_EVENT_DATA_NAME, procnode->proc_pool);

  if (finish_event != NULL)
    SetEvent (*finish_event);
  return APR_SUCCESS;
}

apr_status_t
proc_wait_process (server_rec * main_server, fcgid_procnode * procnode)
{
  apr_status_t rv;
  int exitcode;
  apr_exit_why_e exitwhy;

  if ((rv = apr_proc_wait (procnode->proc_id, &exitcode, &exitwhy,
			   APR_NOWAIT)) != APR_CHILD_NOTDONE)
    {
      /* Log why and how it die */
      proc_print_exit_info (procnode, exitcode, exitwhy, main_server);

      /* Register the death */
      register_termination (main_server, procnode);

      /* Destroy pool */
      apr_pool_destroy (procnode->proc_pool);
      procnode->proc_pool = NULL;
    }

  return rv;
}

static apr_status_t
ipc_handle_cleanup (void *thehandle)
{
  fcgid_namedpipe_handle *handle = thehandle;

  if (handle->handle_pipe != INVALID_HANDLE_VALUE)
    CloseHandle (handle->handle_pipe);
  if (handle->overlap_read.hEvent != NULL)
    CloseHandle (handle->overlap_read.hEvent);
  if (handle->overlap_write.hEvent != NULL)
    CloseHandle (handle->overlap_write.hEvent);

  return APR_SUCCESS;
}

apr_status_t
proc_connect_ipc (server_rec * main_server,
		  fcgid_procnode * procnode, fcgid_ipc * ipc_handle)
{
  /* Prepare the ipc struct */
  fcgid_namedpipe_handle *handle_info;
  ipc_handle->ipc_handle_info =
    (fcgid_namedpipe_handle *) apr_pcalloc (ipc_handle->request_pool,
					    sizeof (fcgid_namedpipe_handle));
  if (!ipc_handle->ipc_handle_info)
    return APR_ENOMEM;

  handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

  /* Prepare OVERLAPPED struct for non-block I/O */
  handle_info->overlap_read.hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  handle_info->overlap_write.hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);

  apr_pool_cleanup_register (ipc_handle->request_pool,
			     handle_info,
			     ipc_handle_cleanup, apr_pool_cleanup_null);

  if (handle_info->overlap_read.hEvent == NULL
      || handle_info->overlap_write.hEvent == NULL)
    return APR_ENOMEM;

  /* Connect to name pipe */
  handle_info->handle_pipe = CreateFile (procnode->socket_path, GENERIC_READ | GENERIC_WRITE, 0,	/* no sharing */
					 NULL,	/* no security attributes */
					 OPEN_EXISTING,	/* opens existing pipe */
					 /*0 */ FILE_FLAG_OVERLAPPED,
					 NULL /* no template file */ );

  if (handle_info->handle_pipe == INVALID_HANDLE_VALUE
      && ipc_handle->connect_timeout != 0
      && GetLastError () == ERROR_PIPE_BUSY)
    {
      /* Wait a while and try again */
      if (WaitNamedPipe (procnode->socket_path, ipc_handle->connect_timeout))
	{
	  handle_info->handle_pipe = CreateFile (procnode->socket_path, GENERIC_READ | GENERIC_WRITE, 0,	/* no sharing */
						 NULL,	/* no security attributes */
						 OPEN_EXISTING,	/* opens existing pipe */
						 0,	/* default attributes */
						 NULL /* no template file */
						 );
	}
    }

  if (handle_info->handle_pipe == INVALID_HANDLE_VALUE)
    {
      if (GetLastError () == ERROR_FILE_NOT_FOUND)	/* The process has exited */
	ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, main_server,
		      "mod_fcgid: can't connect to named pipe, fastcgi server %d has been terminated",
		      procnode->proc_id->pid);
      else
	ap_log_error (APLOG_MARK, APLOG_DEBUG, apr_get_os_error (),
		      main_server,
		      "mod_fcgid: can't connect to named pipe, fastcgi server pid: %d",
		      procnode->proc_id->pid);
      return APR_ESPIPE;
    }

  /* Now named pipe connected */
  return APR_SUCCESS;
}

static BOOL
read_fcgi_header (server_rec * main_server,
		  fcgid_ipc * ipc_handle, FCGI_Header * header)
{
  apr_size_t has_read = 0;
  char *readbuf = (char *) header;
  apr_status_t rv;
  fcgid_namedpipe_handle *handle_info;
  handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

  while (has_read < sizeof (*header))
    {
      DWORD bytesread;
      if (ReadFile (handle_info->handle_pipe, readbuf + has_read,
		    sizeof (*header) - has_read,
		    &bytesread, &handle_info->overlap_read))
	{
	  has_read += bytesread;
	  continue;
	}
      else if ((rv = GetLastError ()) != ERROR_IO_PENDING)
	{
	  ap_log_error (APLOG_MARK, APLOG_WARNING, rv,
			main_server,
			"mod_fcgid: can't read header from pipe");
	  return FALSE;
	}
      else
	{
	  /* it's ERROR_IO_PENDING */
	  DWORD transferred;
	  DWORD dwWaitResult
	    = WaitForSingleObject (handle_info->overlap_read.hEvent,
				   ipc_handle->communation_timeout * 1000);
	  if (dwWaitResult == WAIT_OBJECT_0)
	    {
	      if (!GetOverlappedResult (handle_info->handle_pipe,
					&handle_info->overlap_read,
					&transferred, FALSE /* don't wait */ )
		  || transferred == 0)
		{
		  ap_log_error (APLOG_MARK, APLOG_WARNING,
				apr_get_os_error (), main_server,
				"mod_fcgid: get overlap result error");
		  return FALSE;
		}

	      has_read += transferred;
	      continue;
	    }
	  else
	    {
	      ap_log_error (APLOG_MARK, APLOG_WARNING, 0,
			    main_server,
			    "mod_fcgid: read header timeout from pipe");
	      return FALSE;
	    }
	}
    }

  return TRUE;
}

static BOOL
handle_fcgi_body (server_rec * main_server,
		  fcgid_ipc * ipc_handle,
		  FCGI_Header * header,
		  apr_bucket_brigade * brigade_recv,
		  apr_bucket_alloc_t * alloc)
{
  fcgid_namedpipe_handle *handle_info;
  apr_status_t rv;
  apr_size_t readsize, has_read;
  char *readbuf;

  handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

  if (header->type == FCGI_STDERR
      || header->type == FCGI_STDOUT || header->type == FCGI_END_REQUEST)
    {
      readsize = header->contentLengthB1;
      readsize <<= 8;
      readsize += header->contentLengthB0;
      readsize += header->paddingLength;
      readbuf = apr_bucket_alloc (readsize + 1 /* ending '\0' */ , alloc);
      if (!readbuf)
	{
	  ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
			main_server,
			"mod_fcgid: can't alloc memory for respond: %d",
			readsize + 1);
	  return FALSE;
	}

      /* Read the respond from fastcgi server */
      has_read = 0;
      while (has_read < readsize)
	{
	  DWORD bytesread;
	  if (ReadFile (handle_info->handle_pipe, readbuf + has_read,
			readsize - has_read, &bytesread,
			&handle_info->overlap_read))
	    {
	      has_read += bytesread;
	      continue;
	    }
	  else if ((rv = GetLastError ()) != ERROR_IO_PENDING)
	    {
	      ap_log_error (APLOG_MARK, APLOG_WARNING, rv,
			    main_server, "mod_fcgid: can't read from pipe");
	      return FALSE;
	    }
	  else
	    {
	      /* it's ERROR_IO_PENDING */
	      DWORD transferred;
	      DWORD dwWaitResult
		= WaitForSingleObject (handle_info->overlap_read.hEvent,
				       ipc_handle->communation_timeout *
				       1000);
	      if (dwWaitResult == WAIT_OBJECT_0)
		{
		  if (!GetOverlappedResult (handle_info->handle_pipe,
					    &handle_info->overlap_read,
					    &transferred,
					    FALSE /* don't wait */ )
		      || transferred == 0)
		    {
		      ap_log_error (APLOG_MARK, APLOG_WARNING,
				    apr_get_os_error (), main_server,
				    "mod_fcgid: get overlap result error");
		      return FALSE;
		    }

		  has_read += transferred;
		  continue;
		}
	      else
		{
		  ap_log_error (APLOG_MARK, APLOG_WARNING, 0,
				main_server,
				"mod_fcgid: read timeout from pipe");
		  return FALSE;
		}
	    }
	}
      readbuf[readsize] = '\0';

      /* Now dispatch the respond */
      if (header->type == FCGI_STDERR)
	{
	  /* Write to log, skip the empty contain, and empty line */
	  int content_len = header->contentLengthB1;
	  content_len <<= 8;
	  content_len += header->contentLengthB0;
	  if (!((content_len == 1 && readbuf[0] == '\r')
		|| (content_len == 1 && readbuf[0] == '\n')
		|| (content_len == 2 && readbuf[0] == '\r'
		    && readbuf[1] == '\n') || content_len == 0))
	    {
	      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
			    main_server, "mod_fcgid: cgi stderr log: %s",
			    readbuf);
	    }
	  apr_bucket_free (readbuf);
	  return TRUE;
	}
      else if (header->type == FCGI_END_REQUEST)
	{
	  /* End of the respond */
	  apr_bucket_free (readbuf);
	  return TRUE;
	}
      else if (header->type == FCGI_STDOUT)
	{
	  /* Append the respond to brigade_stdout */
	  apr_bucket *bucket_stdout = apr_bucket_heap_create (readbuf,
							      readsize,
							      apr_bucket_free,
							      alloc);
	  if (!bucket_stdout)
	    {
	      apr_bucket_free (readbuf);
	      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
			    main_server,
			    "mod_fcgid: can't alloc memory for stdout bucket");
	      return FALSE;
	    }

	  /* Append it now */
	  APR_BRIGADE_INSERT_TAIL (brigade_recv, bucket_stdout);
	  return TRUE;
	}
    }

  /* I have no idea about the type of the header */
  ap_log_error (APLOG_MARK, APLOG_WARNING, 0,
		main_server, "mod_fcgid: invalid respond type: %d",
		header->type);
  return FALSE;
}

apr_status_t
proc_bridge_request (server_rec * main_server,
		     fcgid_ipc * ipc_handle,
		     apr_bucket_brigade * birgade_send,
		     apr_bucket_brigade * brigade_recv,
		     apr_bucket_alloc_t * alloc)
{
  fcgid_namedpipe_handle *handle_info;
  apr_bucket *bucket_request;
  apr_status_t rv;
  FCGI_Header fcgi_header;
  DWORD transferred;

  handle_info = (fcgid_namedpipe_handle *) ipc_handle->ipc_handle_info;

  /* 
     Try read data to brigade_recv and write data from birgade_send
     Loop until get read/write error or get "end request" struct 
     from fastcgi application server
   */

  APR_BRIGADE_FOREACH (bucket_request, birgade_send)
  {
    char *write_buf;
    apr_size_t write_buf_len;
    apr_size_t has_write;

    if (APR_BUCKET_IS_EOS (bucket_request))
      break;

    if (APR_BUCKET_IS_FLUSH (bucket_request))
      continue;

    if ((rv = apr_bucket_read (bucket_request, &write_buf, &write_buf_len,
			       APR_BLOCK_READ)) != APR_SUCCESS)
      {
	ap_log_error (APLOG_MARK, APLOG_WARNING, rv,
		      main_server,
		      "mod_fcgid: can't read request from bucket");
	return rv;
      }

    /* Write the buffer to fastcgi server */
    has_write = 0;
    while (has_write < write_buf_len)
      {
	DWORD byteswrite;
	if (WriteFile (handle_info->handle_pipe,
		       write_buf + has_write,
		       write_buf_len - has_write,
		       &byteswrite, &handle_info->overlap_write))
	  {
	    has_write += byteswrite;
	    continue;
	  }
	else if ((rv = GetLastError ()) != ERROR_IO_PENDING)
	  {
	    ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
			  main_server, "mod_fcgid: can't write to pipe");
	    return rv;
	  }
	else
	  {
	    /* 
	       it's ERROR_IO_PENDING on write
	     */

	    /* It's IO pending on write,
	       but if any data I can read from pipe? */
	    DWORD BytesRead, dwWaitResult;
	    while (PeekNamedPipe (handle_info->handle_pipe, &fcgi_header,
				  sizeof (fcgi_header), &BytesRead, NULL,
				  NULL) && BytesRead == sizeof (fcgi_header))
	      {
		/* I get something to read */
		if (!read_fcgi_header (main_server,
				       ipc_handle, &fcgi_header)
		    || !handle_fcgi_body (main_server,
					  ipc_handle, &fcgi_header,
					  brigade_recv, alloc))
		  return APR_ESPIPE;

		/* Is it "end request" respond? */
		if (fcgi_header.type == FCGI_END_REQUEST)
		  return APR_SUCCESS;
	      }

	    /* Now there is nothing to read, so 
	       let's see the sending data finish or not */
	    dwWaitResult
	      = WaitForSingleObject (handle_info->overlap_write.hEvent,
				     ipc_handle->communation_timeout * 1000);
	    if (dwWaitResult == WAIT_OBJECT_0)
	      {
		if (!GetOverlappedResult (handle_info->handle_pipe,
					  &handle_info->overlap_write,
					  &transferred,
					  FALSE /* don't wait */ )
		    || transferred == 0)
		  {
		    ap_log_error (APLOG_MARK, APLOG_WARNING,
				  apr_get_os_error (), main_server,
				  "mod_fcgid: get overlap result error");
		    return APR_ESPIPE;
		  }
		has_write += transferred;
		continue;
	      }
	    else
	      {
		ap_log_error (APLOG_MARK, APLOG_WARNING, 0,
			      main_server,
			      "mod_fcgid: write timeout to pipe");
		return APR_ESPIPE;
	      }
	  }
      }
  }

  /* Now I have send all to fastcgi server, and not get the "end request"
     respond yet, so I keep reading until I get one */
  while (1)
    {
      if (!read_fcgi_header (main_server, ipc_handle, &fcgi_header)
	  || !handle_fcgi_body (main_server, ipc_handle, &fcgi_header,
				brigade_recv, alloc))
	return APR_ESPIPE;
      if (fcgi_header.type == FCGI_END_REQUEST)
	return APR_SUCCESS;
    }
}

apr_status_t
proc_close_ipc (fcgid_ipc * ipc_handle)
{
  return apr_pool_cleanup_run (ipc_handle->request_pool,
			       ipc_handle->ipc_handle_info,
			       ipc_handle_cleanup);
}

void
proc_print_exit_info (fcgid_procnode * procnode, int exitcode,
		      apr_exit_why_e exitwhy, server_rec * main_server)
{
  char *cgipath = NULL;
  char *diewhy = NULL;
  char key_name[_POSIX_PATH_MAX];

  /* Get the file name infomation base on inode and deviceid */
  apr_snprintf (key_name, _POSIX_PATH_MAX, "%lX%lX",
		procnode->inode, procnode->deviceid);
  apr_pool_userdata_get (&cgipath, key_name, g_inode_cginame_map);

  /* Reasons to exit */
  switch (procnode->diewhy)
    {
    case FCGID_DIE_KILLSELF:
      if (exitwhy == APR_PROC_EXIT)
	diewhy = "normal exit";
      else
	diewhy = "access violation";
      break;
    case FCGID_DIE_IDLE_TIMEOUT:
      diewhy = "idle timeout";
      break;
    case FCGID_DIE_LIFETIME_EXPIRED:
      diewhy = "lifetime expired";
      break;
    case FCGID_DIE_BUSY_TIMEOUT:
      diewhy = "busy timeout";
      break;
    case FCGID_DIE_CONNECT_ERROR:
      diewhy = "connect error, server may has exited";
      break;
    case FCGID_DIE_COMM_ERROR:
      diewhy = "communication error";
      break;
    case FCGID_DIE_SHUTDOWN:
      diewhy = "shutting down";
      break;
    default:
      diewhy = "unknow";
    }

  /* Print log now */
  if (cgipath)
    ap_log_error (APLOG_MARK, APLOG_INFO, 0, main_server,
		  "mod_fcgid: process %s(%d) exit(%s), return code %d",
		  cgipath, procnode->proc_id->pid, diewhy, exitcode);
  else
    ap_log_error (APLOG_MARK, APLOG_WARNING, 0, main_server,
		  "mod_fcgid: can't get cgi name while exiting, exitcode: %d",
		  exitcode);
}
