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
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ctype.h>


#define REGEX_MAX_SIZE 6
#define MAX_STRING_SIZE 256
#define MAX_BUF_SIZE 2056
#define FTP_SEND_CODE 0512

#define RESPONSE_SUCCESS_CONNECTION 220
#define RESPONSE_SUCCESS_LOGIN 230
#define RESPONSE_PASSIVE_MODE 227
#define RESPONSE_SUCCESS_TYPE 200
#define RESPONSE_SUCCESS_SIZE 213

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

#define REGEX_NOPORT "ftp://([^:]+):([^@]+)@([^/]+)/(.+)"
// ftp://myname:rubem@host.dom/%2Fetc/motd

#define REGEX_ONLYPORT "ftp://([^:]+):([0-9]+)/(.+)"
// ftp://host.dom:21/%2Fetc/motd

#define REGEX_ONLYNAME "ftp://([^@]+)@([^/]+)/(.+)"
// ftp://rubem@host.dom/%2Fetc/motd

#define REGEX_ONLYHOST "ftp://([^/]+)/(.+)"
// ftp://host.dom/%2Fetc/motd

#define REGEX_PASSIVE ".*\\(([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)\\).*"

int ftp_parse(URL *url, char *input) {
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
    // printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
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
    //  printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
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
    sprintf(url->username,"%s","anonymous");
    sprintf(url->password,"%s","anonymous");
    sprintf(url->host,"%s",strndup(input + group_array[1].rm_so,group_array[1].rm_eo - group_array[1].rm_so));
    sprintf(url->port,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->path,"%s",strndup(input + group_array[3].rm_so,group_array[3].rm_eo - group_array[3].rm_so));
    // printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
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
    sprintf(url->password,"%s","anonymous");
    sprintf(url->host,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->port,"%s","21");
    //sprintf(url->port,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->path,"%s",strndup(input + group_array[3].rm_so,group_array[3].rm_eo - group_array[3].rm_so));
    // printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
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
    sprintf(url->username,"%s","anonymous");
    sprintf(url->password,"%s","anonymous");
    sprintf(url->host,"%s",strndup(input + group_array[1].rm_so,group_array[1].rm_eo - group_array[1].rm_so));
    sprintf(url->port,"%s","21");
    //sprintf(url->port,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(url->path,"%s",strndup(input + group_array[2].rm_so,group_array[2].rm_eo - group_array[2].rm_so));
    // printf("%s\n%s\n%s\n%s\n%s\n",url->username,url->password,url->host,url->port,url->path);
    return 0;
  }
  regfree(&regex);

  return 1;
}


int ftp_create_socket(char *host, char *port) {

  struct hostent *h;  

  if((h = gethostbyname(host)) == NULL) {
    printf("error to get host\n");
    return -1;
  }

  char *server_ip = inet_ntoa(*((struct in_addr *) h->h_addr));
  int server_port = atoi(port);

  int sockfd;
  struct sockaddr_in server_addr;

  bzero((char *) &server_addr,sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(server_ip);
  server_addr.sin_port = htons(server_port);

  if((sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0) {
    printf("error creating a socket\n");
    return -1;
  }

  if(connect(sockfd, (struct sockaddr *) &server_addr,sizeof(server_addr)) < 0) {
    printf("error while connecting socket\n");
    return -1;
  }

  return sockfd;
}

int ftp_read_control(int sockfd,char *buffer) {
  sleep(2);
  char buf[MAX_BUF_SIZE];
  read(sockfd,&buf,MAX_BUF_SIZE);
  buf[strcspn(buf,"\n")] = '\0';

  printf("response :%s\n",buf);
  strcpy(buffer,buf);
  return 0;
}

int ftp_read_code(char *buf) {
  char s[8];
  int i = 0;
  while(isdigit(buf[i]) && i < 3) {
    s[i] = buf[i];
    i++;
  }
  s[i + 1] = '\0';
  return atoi(s) % 1000;
}

int ftp_login(int sockfd, URL url) {
  char user[MAX_BUF_SIZE];
  char password[MAX_BUF_SIZE];
  char response[MAX_BUF_SIZE];

  sprintf(user,"USER %s\r\n",url.username);
  sprintf(password,"PASS %s\r\n",url.password);

  printf("[login] started\n");

  // SEND USER
  if(write(sockfd,user,strlen(user)) == -1) {
    printf("[login] error to send USER %s\n",user);
    return 1;
  }
  printf("[login] sent user\n");

  ftp_read_control(sockfd,response);

  printf("[login] received %d\n",ftp_read_code(response));
  if(ftp_read_code(response) != RESPONSE_SUCCESS_CONNECTION) {
    printf("[login] error while logging in (USER)\n");
    return 1;
  }
  printf("[login] user success\n");

  // SEND PASS
  if(write(sockfd,password,strlen(password)) == -1) {
    printf("[login] error to send PASS %s\n",password);
    return 1;
  }
  printf("[login] sent pass\n");

  ftp_read_control(sockfd,response);
  int response_code = ftp_read_code(response);

  printf("[login] received %d\n",ftp_read_code(response));
  if(ftp_read_code(response) != RESPONSE_SUCCESS_LOGIN) {
    printf("[login] error while logging in (PASS)\n");
    return 1;
  }
  printf("[login] pass success\n");


  printf("[login] success\n");
  return 0;
}

int ftp_set_passive(int sockfd, char *passive_host,char *passive_port) {
  printf("[passive] set passive started\n");

  char *passive_str = "pasv\r\n";
  char response[MAX_BUF_SIZE];

  if(write(sockfd,passive_str,strlen(passive_str)) == -1) {
    printf("[passive] failed to send PASS\n");
    return 1;
  }

  ftp_read_control(sockfd,response);
  int response_code = ftp_read_code(response);

  if(response_code != RESPONSE_PASSIVE_MODE) {
    printf("[passive] failed while receiving response\n");
    return 1;
  }

  regex_t regex;
  int group_size = 7;
  regmatch_t group_array[group_size];
  char p1[MAX_STRING_SIZE];
  char p2[MAX_STRING_SIZE];
  char p3[MAX_STRING_SIZE];
  char p4[MAX_STRING_SIZE];
  char pp1[MAX_STRING_SIZE];
  char pp2[MAX_STRING_SIZE];

  // FULL
  if(regcomp(&regex,REGEX_PASSIVE,REG_EXTENDED) != 0) {
    printf("failed to compile full regex");
    return 1;
  }

  if(regexec(&regex,response,group_size,group_array,0) == 0) {
    printf("match: passive\n");
    unsigned int g = 0;
    sprintf(p1,"%s",strndup(response + group_array[1].rm_so, group_array[1].rm_eo - group_array[1].rm_so));
    sprintf(p2,"%s",strndup(response + group_array[2].rm_so, group_array[2].rm_eo - group_array[2].rm_so));
    sprintf(p3,"%s",strndup(response + group_array[3].rm_so, group_array[3].rm_eo - group_array[3].rm_so));
    sprintf(p4,"%s",strndup(response + group_array[4].rm_so, group_array[4].rm_eo - group_array[4].rm_so));
    sprintf(pp1,"%s",strndup(response + group_array[5].rm_so, group_array[5].rm_eo - group_array[5].rm_so));
    sprintf(pp2,"%s",strndup(response + group_array[6].rm_so, group_array[6].rm_eo - group_array[6].rm_so));
  }

  sprintf(passive_host,"%s.%s.%s.%s",p1,p2,p3,p4);
  int port = atoi(pp1)*256 + atoi(pp2);
  sprintf(passive_port,"%d",port);

  return 0;
}

int ftp_get_file_size(int sockfd, URL url) {
  char response[MAX_BUF_SIZE]; 

  char *set_type_str = "TYPE I\r\n";
  if(write(sockfd,set_type_str,strlen(set_type_str)) == -1) {
    printf("[read size] failed to send TYPE I\n");
    return -1;
  }

  ftp_read_control(sockfd,response);
  int response_code = ftp_read_code(response);
/*   printf("%s\n",response);
  printf("%d\n",response_code); */

  if(response_code != RESPONSE_SUCCESS_TYPE) {
    printf("[read size] failed on response (TYPE I)\n");
    return -1;
  }

  char get_file_size_str[MAX_BUF_SIZE];
  sprintf(get_file_size_str,"SIZE %s\r\n",url.path);

  if(write(sockfd,get_file_size_str,strlen(get_file_size_str)) == -1) {
    printf("[read size] failed to send SIZE [PATH]\n");
    return -1;
  }

  ftp_read_control(sockfd,response);
  response_code = ftp_read_code(response);
/*   printf("%s\n",response);
  printf("%d\n",response_code); */

  if(response_code != RESPONSE_SUCCESS_SIZE) {
    printf("[read size] failed on response (SIZE [PATH])\n");
    return -1;
  }

  char *s = strtok(response," ");
  s = strtok(NULL," ");
  return atoi(s);
}

int ftp_transfer_request(int sockfd, URL url) {
  char response[MAX_BUF_SIZE]; 
  char get_file_str[MAX_BUF_SIZE];
  sprintf(get_file_str,"RETR %s\r\n",url.path);

  if(write(sockfd,get_file_str,strlen(get_file_str)) == -1) {
    printf("[request file] failed to send SIZE [PATH]\n");
    return -1;
  }
  printf("[request file] request sent\n");

  ftp_read_control(sockfd,response);
  int response_code = ftp_read_code(response);

  printf("[request file] received %d\n",response_code);
/*   if(response_code != 150 && response_code != 226) {
    printf("[request file] failed on response (RECV %s)\n",url.path);
    return 1;
  } */

  return 0;

}

int ftp_get_file(int sockfd,URL url,int file_size) {
  printf("[download] started to get file\n");

  double total = 0;
  char file_name[MAX_BUF_SIZE] = {0};
  strcat(file_name,"downloads");
  if(strchr(url.path,'/') != NULL) {
    strcat(file_name,strrchr(url.path,'/'));
  } else {
    strcat(file_name,"/");
    strcat(file_name,url.path);
  }

  printf("filepath: %s\n",file_name);


  FILE *fd = fopen(file_name,"wb");

  if(fd == NULL) {
    printf("failed to open the file %s\n",file_name);
    return 1;
  }

  char buffer[MAX_BUF_SIZE];
  int bytes_read;
  printf("[download] download started\n");
  do {
    bytes_read = recv(sockfd,buffer,MAX_BUF_SIZE,0);
    total += bytes_read;
    if (fwrite(buffer,bytes_read,1,fd) < 0) {
      printf("failed to load chunk \n");
      return 1;
    }
    printf("progress: %0.2f\n",(total/file_size)*100);
  } while(bytes_read);

  fclose(fd);

  printf("[download] download finished\n");
  return 0;
}

int ftp_quit(int sockfd) {
  char *quit_str = "QUIT\r\n";
  printf("[quit] started\n");

  if(write(sockfd,quit_str,strlen(quit_str)) == -1) {
    printf("[quit] failed to quit\n");
    return 1;
  }
  printf("[quit] sent quit\n");
  printf("[quit] success\n");
  return 0;
}

int main(int argc, char *argv[]) {

  struct URL url;
  char passive_host[MAX_STRING_SIZE];
  char passive_port[MAX_STRING_SIZE];

  if (argc != 2 ) {
    fprintf(stderr,"Usage: %s <url>\n",argv[0]);
    return 1;
  }

  if (ftp_parse(&url,argv[1]) != 0) {
    printf("error to parse\n");
    return 1;
  }

  int sockfd = ftp_create_socket(url.host,url.port);

  if(sockfd == -1) {
    printf("error to create socket\n");
    return 1;
  }

  if(ftp_login(sockfd,url) != 0) {
    printf("error to login\n");
    return 1;
  }

  if(ftp_set_passive(sockfd,passive_host,passive_port) != 0) {
    printf("error to set passive\n");
    return 1;
  }

  int passive_sockfd = ftp_create_socket(passive_host,passive_port);

  if(passive_sockfd == -1) {
    printf("error to create socket\n");
    return 1;
  }

  int file_size = ftp_get_file_size(sockfd,url);
  if(file_size == -1) {
    printf("failed to get file size\n");
    return 1;
  }

  printf("file size: %d\n",file_size);

  if(ftp_transfer_request(sockfd,url) != 0) {
    printf("failed to request transfer\n");
    return 1;
  }

  if(ftp_get_file(passive_sockfd,url,file_size) != 0) {
    printf("failed to get file\n");
    return 1;
  }

  if(ftp_quit(sockfd) != 0) {
    printf("failed to quit\n");
    return 1;
  }


  printf("closing sockets\n");
  close(sockfd);
  close(passive_sockfd);

  return 0;
}