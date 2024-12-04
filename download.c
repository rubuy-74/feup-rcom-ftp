// regexes
// parse input
// has data (???)
// login
// get file size
// enter passive mode
// get file size
// get file
// quit

// main
#include <regex.h>
#include <stdio.h>
#include <string.h>

#define REGEX_MAX_SIZE 6
#define MAX_STRING_SIZE 256

typedef struct URL {
  char username[MAX_STRING_SIZE];
  char password[MAX_STRING_SIZE];
  char host[MAX_STRING_SIZE];
  char path[MAX_STRING_SIZE];
  char port[MAX_STRING_SIZE];
} URL;


// ftp://myname:rubem@host.dom:21/%2Fetc/motd


#define REGEX_FULL "ftp://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)"
// ftp://myname:rubem@host.dom:21/%2Fetc/motd

#define REGEX_NOPASS "ftp://([^@]+)@([^:]+):([0-9]+)/(.+)"
// ftp://myname@host.dom:21/%2Fetc/motd

#define REGEX_NOPORT "ftp://([^:]+):([^@]+)@([^:]+)/(.+)"
// ftp://myname:rubem@host.dom/%2Fetc/motd

#define REGEX_ONLYPORT "ftp://([^:]+):([0-9]+)/(.+)"
// ftp://host.dom:21/%2Fetc/motd

#define REGEX_ONLYNAME "ftp://([^@]+)@([^/]+)/(.+)"
// ftp://rubem@host.dom/%2Fetc/motd

#define REGEX_ONLYHOST "ftp://([^/]+)/(.+)"
// ftp://host.dom/%2Fetc/motd

int parse(URL *url, char *input) {
  regex_t regex;
  int group_size = REGEX_MAX_SIZE;
  regmatch_t group_array[group_size];

  // FULL
  if(regcomp(&regex,REGEX_FULL,REG_EXTENDED) != 0) {
    printf("failed to compile full regex");
    return 1;
  }
  if (regexec(&regex,input,group_size,group_array,0) == 0) {
    printf("match: full\n");
    sprintf(url->username,"%s",strndup(input + group_array[1].rm_so,group_array[1].rm_eo - group_array[1].rm_so));
    sprintf(url->password,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->host,"%s",strndup(input + group_array[3].rm_so,group_array[3].rm_eo - group_array[3].rm_so));
    sprintf(url->port,"%s",strndup(input + group_array[4].rm_so,group_array[4].rm_eo - group_array[4].rm_so));
    sprintf(url->path,"%s",strndup(input + group_array[5].rm_so,group_array[5].rm_eo - group_array[5].rm_so));
    printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
    return 0;
  }
  regfree(&regex);

  // NO PASS
  if(regcomp(&regex,REGEX_NOPASS,REG_EXTENDED) != 0) {
    printf("failed to compile full regex");
    return 1;
  }

  if (regexec(&regex,input,group_size,group_array,0) == 0) {
    printf("match: nopass\n");
    sprintf(url->username,"%s",strndup(input + group_array[1].rm_so,group_array[1].rm_eo - group_array[1].rm_so));
    printf("password please (uwu) [empty = anonymous]: ");
    fgets(url->password,MAX_STRING_SIZE,stdin);
    url->password[strlen(url->password)-1] = 0;
    if(strlen(url->password) == 0) {
      sprintf(url->password,"%s","anonymous");
    }
    sprintf(url->host,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->port,"%s",strndup(input + group_array[3].rm_so,group_array[3].rm_eo - group_array[3].rm_so));
    sprintf(url->path,"%s",strndup(input + group_array[4].rm_so,group_array[4].rm_eo - group_array[4].rm_so));
    printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
    return 0;
  }
  regfree(&regex);

  // NOPORT
  if(regcomp(&regex,REGEX_NOPORT,REG_EXTENDED) != 0) {
    printf("failed to compile full regex");
    return 1;
  }
  if (regexec(&regex,input,group_size,group_array,0) == 0) {
    printf("match: noport\n");
    sprintf(url->username,"%s",strndup(input + group_array[1].rm_so,group_array[1].rm_eo - group_array[1].rm_so));
    sprintf(url->password,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->host,"%s",strndup(input + group_array[3].rm_so,group_array[3].rm_eo - group_array[3].rm_so));
    //sprintf(url->port,"%s",strndup(input + group_array[4].rm_so,group_array[4].rm_eo - group_array[4].rm_so));
    sprintf(url->port,"%s","21");
    sprintf(url->path,"%s",strndup(input + group_array[4].rm_so,group_array[4].rm_eo - group_array[4].rm_so));
    printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
    return 0;
  }
  regfree(&regex);

  // ONLYPORT
  if(regcomp(&regex,REGEX_ONLYPORT,REG_EXTENDED) != 0) {
    printf("failed to compile full regex");
    return 1;
  }

  if (regexec(&regex,input,group_size,group_array,0) == 0) {
    printf("match: onlyport\n");
    printf("username please (uwu) [empty = anonymous]: ");
    fgets(url->username,MAX_STRING_SIZE,stdin);
    url->username[strlen(url->username)-1] = 0;
    if(strlen(url->username) == 0) {
      sprintf(url->username,"%s","anonymous");
    }
    printf("password please (uwu) [empty = anonymous]: ");
    fgets(url->password,MAX_STRING_SIZE,stdin);
    url->password[strlen(url->password)-1] = 0;
    if(strlen(url->password) == 0) {
      sprintf(url->password,"%s","anonymous");
    }
    sprintf(url->host,"%s",strndup(input + group_array[1].rm_so,group_array[1].rm_eo - group_array[1].rm_so));
    sprintf(url->port,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->path,"%s",strndup(input + group_array[3].rm_so,group_array[3].rm_eo - group_array[3].rm_so));
    printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
    return 0;
  }
  regfree(&regex);

  // ONLYNAME 
  if(regcomp(&regex,REGEX_ONLYNAME,REG_EXTENDED) != 0) {
    printf("failed to compile full regex");
    return 1;
  }

  if (regexec(&regex,input,group_size,group_array,0) == 0) {
    printf("match: onlyname\n");
    sprintf(url->username,"%s",strndup(input + group_array[1].rm_so,group_array[1].rm_eo - group_array[1].rm_so));
    printf("password please (uwu) [empty = anonymous]: ");
    fgets(url->password,MAX_STRING_SIZE,stdin);
    url->password[strlen(url->password)-1] = 0;
    if(strlen(url->password) == 0) {
      sprintf(url->password,"%s","anonymous");
    }
    sprintf(url->host,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->port,"%s","21");
    //sprintf(url->port,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->path,"%s",strndup(input + group_array[3].rm_so,group_array[3].rm_eo - group_array[3].rm_so));
    printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
    return 0;
  }
  regfree(&regex);
  
  // ONLYHOST
  if(regcomp(&regex,REGEX_ONLYHOST,REG_EXTENDED) != 0) {
    printf("failed to compile full regex");
    return 1;
  }

  if (regexec(&regex,input,group_size,group_array,0) == 0) {
    printf("match: onlyhost\n");
    printf("username please (uwu) [empty = anonymous]: ");
    fgets(url->username,MAX_STRING_SIZE,stdin);
    url->username[strlen(url->username)-1] = 0;
    if(strlen(url->username) == 0) {
      sprintf(url->username,"%s","anonymous");
    }
    printf("password please (uwu) [empty = anonymous]: ");
    fgets(url->password,MAX_STRING_SIZE,stdin);
    url->password[strlen(url->password)-1] = 0;
    if(strlen(url->password) == 0) {
      sprintf(url->password,"%s","anonymous");
    }
    sprintf(url->host,"%s",strndup(input + group_array[1].rm_so,group_array[1].rm_eo - group_array[1].rm_so));
    sprintf(url->port,"%s","21");
    //sprintf(url->port,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->path,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
    return 0;
  }
  regfree(&regex);

  return 0;
}

int main(int argc, char *argv[]) {

  struct URL url;

/*   int passive_host;
  int passive_port;

  char *file_path;

  int socketfd = create_socket(url.host,url.port);
  int passive_socketfd = create_socket(passive_host,passive_port); */
  

  if (parse(&url,argv[1]) != 0) {
    printf("error to parse\n");
    return 1;
  }

/*   if (login(socketfd,url.username,url.password) != 0) {
    printf("error to login\n");
    return 1;
  }

  if (set_passive(passive_socketfd,passive_host,passive_port) != 0) {
    printf("error to set passive\n");
    return 1;
  }

  if (request_transfer(socketfd,url.path) != 0) {
    printf("error to request transfer\n");
    return 1;
  }

  if(get_file(passive_socketfd,file_path) != 0) {
    printf("error to get file\n");
    return 1;
  } 

  char *quit = "QUIT\r\n";
  if(send(socketfd,quit,strlen(quit),0) != 0) {
    print("error while quitting\n");
    return 1;
  }


     */
  return 0;
}