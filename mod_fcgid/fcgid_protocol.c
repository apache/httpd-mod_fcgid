#include "httpd.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_pools.h"
#include "fcgid_global.h"
#include "fcgid_protocol.h"

static size_t
init_environment (char *buf, char **envp)
{
  char *spliter;
  int namelen, valuelen;
  char *cur_buf = buf;
  size_t buffer_size = 0;
  for (; *envp != NULL; envp++)
    {
      spliter = strchr (*envp, '=');
      if (spliter == NULL)
	continue;

      namelen = spliter - *envp;
      valuelen = strlen (spliter + 1);

      /* Put name length to buffer */
      if (namelen < 0x80)
	{
	  if (!buf)
	    buffer_size++;
	  else
	    *cur_buf++ = (unsigned char) namelen;
	}
      else
	{
	  if (!buf)
	    buffer_size += 4;
	  else
	    {
	      *cur_buf++ = (unsigned char) ((namelen >> 24) | 0x80);
	      *cur_buf++ = (unsigned char) (namelen >> 16);
	      *cur_buf++ = (unsigned char) (namelen >> 8);
	      *cur_buf++ = (unsigned char) namelen;
	    }
	}

      /* Put value length to buffer */
      if (valuelen < 0x80)
	{
	  if (!buf)
	    buffer_size++;
	  else
	    *cur_buf++ = (unsigned char) valuelen;
	}
      else
	{
	  if (!buf)
	    buffer_size += 4;
	  else
	    {
	      *cur_buf++ = (unsigned char) ((valuelen >> 24) | 0x80);
	      *cur_buf++ = (unsigned char) (valuelen >> 16);
	      *cur_buf++ = (unsigned char) (valuelen >> 8);
	      *cur_buf++ = (unsigned char) valuelen;
	    }
	}

      /* Now the name and body buffer */
      if (!buf)
	{
	  buffer_size += namelen;
	  buffer_size += valuelen;
	}
      else
	{
	  memcpy (cur_buf, *envp, namelen);
	  cur_buf += namelen;
	  memcpy (cur_buf, spliter + 1, valuelen);
	  cur_buf += valuelen;
	}
    }
  return buffer_size;
}

static void
init_begin_request_body (int role, FCGI_BeginRequestBody * begin_request_body)
{
  begin_request_body->roleB1 = (unsigned char) (((role >> 8) & 0xff));
  begin_request_body->roleB0 = (unsigned char) (role & 0xff);
  begin_request_body->flags = 0;
  memset (begin_request_body->reserved, 0,
	  sizeof (begin_request_body->reserved));
}

int
init_header (int type, int requestId, apr_size_t contentLength,
	     apr_size_t paddingLength, FCGI_Header * header)
{
  if (contentLength > 65535 || paddingLength > 255)
    return 0;
  header->version = FCGI_VERSION_1;
  header->type = (unsigned char) type;
  header->requestIdB1 = (unsigned char) ((requestId >> 8) & 0xff);
  header->requestIdB0 = (unsigned char) (requestId & 0xff);
  header->contentLengthB1 = (unsigned char) ((contentLength >> 8) & 0xff);
  header->contentLengthB0 = (unsigned char) ((contentLength) & 0xff);
  header->paddingLength = (unsigned char) paddingLength;
  header->reserved = 0;
  return 1;
}

int
build_begin_block (server_rec * main_server,
		   apr_bucket_alloc_t * alloc,
		   apr_bucket_brigade * request_brigade)
{
  /* Alloc memory for begin request header & body */
  FCGI_Header *begin_request_header =
    apr_bucket_alloc (sizeof (FCGI_Header), alloc);
  FCGI_BeginRequestBody *begin_request_body =
    apr_bucket_alloc (sizeof (FCGI_BeginRequestBody), alloc);
  apr_bucket *bucket_header =
    apr_bucket_heap_create ((const char *) begin_request_header,
			    sizeof (*begin_request_header), apr_bucket_free,
			    alloc);
  apr_bucket *bucket_body =
    apr_bucket_heap_create ((const char *) begin_request_body,
			    sizeof (*begin_request_body), apr_bucket_free,
			    alloc);

  /* Sanity check */
  if (!begin_request_body || !begin_request_body
      || !bucket_header || !bucket_body)
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    main_server,
		    "mod_fcgid: can't alloc memeory for begin request");
      return 0;
    }

  /* Initialize begin request header and body */
  if (!init_header (FCGI_BEGIN_REQUEST, 1, sizeof (FCGI_BeginRequestBody),
		    0, begin_request_header))
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    main_server,
		    "mod_fcgid: can't init begin request header");
      return 0;
    }
  init_begin_request_body (FCGI_RESPONDER, begin_request_body);

  /* Append the header and body to request brigade */
  APR_BRIGADE_INSERT_TAIL (request_brigade, bucket_header);
  APR_BRIGADE_INSERT_TAIL (request_brigade, bucket_body);

  return 1;
}

int
build_env_block (server_rec * main_server, char **envp,
		 apr_bucket_alloc_t * alloc,
		 apr_bucket_brigade * request_brigade)
{
  /* Get the size of the destination buffer */
  apr_size_t bufsize = init_environment (NULL, envp);

  /* Alloc memory for environment header and body */
  FCGI_Header *env_request_header =
    apr_bucket_alloc (sizeof (FCGI_Header), alloc);
  FCGI_Header *env_empty_header =
    apr_bucket_alloc (sizeof (FCGI_Header), alloc);
  char *buf = apr_bucket_alloc (bufsize, alloc);
  apr_bucket *bucket_header = apr_bucket_heap_create ((const char *)
						      env_request_header,
						      sizeof
						      (*env_request_header),
						      apr_bucket_free, alloc);
  apr_bucket *bucket_body = apr_bucket_heap_create (buf, bufsize,
						    apr_bucket_free, alloc);
  apr_bucket *bucket_empty_header = apr_bucket_heap_create ((const char *)
							    env_empty_header,
							    sizeof
							    (*env_empty_header),
							    apr_bucket_free,
							    alloc);
  if (!env_request_header || !buf || !env_empty_header || !bucket_header
      || !bucket_body || !bucket_empty_header)
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    main_server, "mod_fcgid: can't alloc memory for envion");
      return 0;
    }

  /* Initialize header and body */
  if (!init_header (FCGI_PARAMS, 1, bufsize, 0, env_request_header)
      || !init_header (FCGI_PARAMS, 1, 0, 0, env_empty_header))
    {
      ap_log_error (APLOG_MARK, APLOG_WARNING, apr_get_os_error (),
		    main_server, "mod_fcgid: can't init env request header");
      return 0;
    }
  init_environment (buf, envp);

  /* Append the header and body to request brigade */
  APR_BRIGADE_INSERT_TAIL (request_brigade, bucket_header);
  APR_BRIGADE_INSERT_TAIL (request_brigade, bucket_body);
  APR_BRIGADE_INSERT_TAIL (request_brigade, bucket_empty_header);

  return 1;
}
