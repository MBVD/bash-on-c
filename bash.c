#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#define BUF_MAX 256
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))

enum Type {
  LOGIC, OPERATION, REDIRECT
};

enum Ground {
  FOREGROUND, BACKGROUND
};


typedef struct job {
  pid_t pid;
  char* command;
  struct job* next;
} job;

job* create_job(pid_t pid, const char* command){
  job* tmp = malloc(sizeof(job));
  tmp -> pid = pid;
  tmp -> command = malloc(strlen(command) + 1);
  strcpy(tmp->command, command);
  tmp->next = NULL;
  return tmp;
}

int push_job(job* jobs, pid_t pid, const char* command){
  job* tmp = create_job(pid, command);
  while(jobs -> next != NULL){
    jobs = jobs -> next;
  }
  jobs -> next = tmp;
  return 0;
}

job* jobs = NULL;

int delete_job(job** jobs, pid_t pid){
  job* head = *jobs;
  job* tmp = * jobs;
  job* prev = *jobs;
  while (tmp->pid != pid){
    prev = tmp;
    tmp = tmp -> next;
  }
  if (tmp == head){
    *jobs = head -> next;
    return 0;
  }
  prev -> next = tmp -> next;
  free(tmp);
  return 0;
}

void print_jobs(job* jobs){
  printf("PID | NAME \n");
  while (jobs != NULL){
    printf("%d | %s \n", jobs->pid, jobs -> command);
    jobs = jobs -> next;
  }
  return;
}
typedef struct node {
  enum Type type;
  enum Ground ground;
  char* op;
  char* command;
  struct node* left, *right;
} node;

node* create_node(enum Type type, const char* op, const char* command, node* left, node* right, enum Ground ground){
  node* tmp = (node*)malloc(sizeof(node));
  tmp -> type = type;
  tmp -> ground = ground;
  tmp -> op = op;
  tmp -> command = command;
  tmp -> left = left;
  tmp -> right = right;
  return tmp;
}

node* parse_continue_expr(int* i, char** commands);
node* parse_or_expr(int* i, char** commands);
node* parse_and_expr(int* i, char** commands);
node* parse_command_expr(int *i, char** commands);
node* parse_redirect_left(int* i, char** commands);
node* parse_redirect_right(int* i, char** commands);
node* parse_pipe_expr(int* i, char** commands);

node* parse(char** commands){
  printf("start parsing \n");
  int i = 0;
  return parse_redirect_right(&i, commands);
}

int is_redirect_left(const char* c){
  return !strcmp(c, "<") || !strcmp(c, "<<");
}

int is_redirect_right(const char* c) {
  return !strcmp(c, ">") || !strcmp(c, ">>");
}

node* parse_continue_expr(int* i, char** commands){
  printf("start ; parsing \n");
  node* left = parse_or_expr(i, commands);
  printf("stop parsing || \n");
  while(commands[*i] != NULL && !strcmp(commands[*i], ";")){
    (*i)++;
    node* right = parse_continue_expr(i, commands);
    left = create_node(LOGIC, ";", NULL, left, right, FOREGROUND);
  }
  return left;
}

node* parse_or_expr(int* i, char** commands){
  printf("start || parsing \n");
  node* left = parse_and_expr(i, commands);
  printf("stop parsing && \n");
  while(commands[*i] != NULL && !strcmp(commands[*i], "||")){
    (*i)++;
    node* right = parse_or_expr(i, commands);
    left = create_node(LOGIC, "||", NULL, left, right, FOREGROUND);
  }
  return left;
}

node* parse_and_expr(int* i, char** commands){
  printf("start && parsing \n");
  node* left = parse_pipe_expr(i, commands);
  printf("stop parsing command \n");
  while(commands[*i] != NULL && !strcmp(commands[*i], "&&")) {
    (*i)++;
    node* right = parse_and_expr(i, commands);
    left = create_node(LOGIC, "&&", NULL, left, right, FOREGROUND);
  }
  return left;
}

node* parse_pipe_expr(int *i, char** commands){
  printf("start | parsing \n");
  node* left = parse_redirect_right(i, commands);
  printf("stop parsing ; \n");
  while (commands[*i] != NULL && !strcmp(commands[*i], "|")) {
    char* op = malloc(strlen(commands[*i]));
    strcpy(op, commands[*i]);
    (*i)++;
    node* right = parse_pipe_expr(i, commands);
    left = create_node(REDIRECT, op, NULL, left, right, FOREGROUND);
  }
  return left;
}

node* parse_redirect_right(int *i, char** commands) {
  printf("start > parsing \n");
  node* left = parse_redirect_left(i, commands);
  printf("stop parsing < \n");
  while (commands[*i] != NULL && is_redirect_right(commands[*i])) {
    char* op = malloc(strlen(commands[*i]));
    strcpy(op, commands[*i]);
    (*i)++;
    node* right = parse_redirect_right(i, commands);
    left = create_node(REDIRECT, op, NULL, left, right, FOREGROUND);
  }
  return left;
}

node* parse_redirect_left(int * i, char** commands) {
  printf("start < parsing \n");
  node* left = parse_command_expr(i, commands);
  printf("stop parsing | \n");
  while (commands[*i] != NULL && is_redirect_left(commands[*i])) {
    char* op = malloc(strlen(commands[*i]));
    strcpy(op, commands[*i]);
    (*i)++;
    node* right = parse_redirect_left(i, commands);
    left = create_node(REDIRECT, op, NULL, left, right, FOREGROUND);
  }
  return left;
}

node* parse_command_expr(int *i, char** commands){
  printf("command here : %s \n", commands[*i]);
  node* command_node = create_node(OPERATION, NULL, commands[*i], NULL, NULL, FOREGROUND);
  (*i)++;
  if (commands[*i] != NULL && !strcmp(commands[*i], "&")){
    command_node -> ground = BACKGROUND;
    (*i)++;
  }
  return command_node;
}

void print_tree(node* root){
  if (root -> type == LOGIC || root -> type == REDIRECT){
    print_tree(root->left);
    printf(" %s ", root -> op);
    print_tree(root -> right);
  }
  if (root -> type == OPERATION){
    printf("%s", root -> command);
  }
}

void free_tree(node* root) {
  if (root == NULL){
    return ;
  }
  free_tree(root->left);
  free_tree(root->right);
  free(root);
}


int is_spec (const char c){
  return (c == '|' || c == '&' || c == ';' || c == '>' || c == '<');
}

char** split(const char* s){
  int n = 0;
  for (int i = 0; s[i] != '\0'; i++){
    if (is_spec(s[i])){
      n++;
      while(s[i] == '|' || s[i] == '&'){
        i++;
      }
    }
  }
  if (n) n = 2 * n + 1;
  else if (s[0] != '\0'){
    n = 1;
  }
  else return NULL;
  char** array = (char**)malloc((n + 1) * sizeof(char*));
  array[n] = NULL;
  int tmp_size = BUF_MAX, array_i = 0;
  char* tmp = malloc(tmp_size);
  int tmp_i = 0;
  for (int i = 0; s[i] != '\0'; i++){
    if ((is_spec(s[i]) && !is_spec(tmp[0])) || (is_spec(tmp[0]) && !is_spec(s[i]))){
      tmp[tmp_i] = '\0';
      array[array_i] = (char*)malloc(tmp_i);
      strcpy(array[array_i++], tmp);
      tmp_i = 0;
      while (s[i] == ' ') i++; // скипаю все пробелы
      tmp[tmp_i++] = s[i];
      continue;
    }
    if (s[i] == ' '){
      while (s[i+1] == ' ') i++; // скипаю все пробелы
      if (is_spec(s[i + 1])){
        continue;
      }else{
        tmp[tmp_i++] = ' ';
        continue;
      }
    }
    tmp[tmp_i++] = s[i];
    if (tmp_i >= tmp_size){
      tmp_size += BUF_MAX;
      tmp = (char*)realloc(tmp, tmp_size);
    }
  }
  if (n){
    tmp[tmp_i] = '\0';
    array[array_i] = (char*)malloc(tmp_i);
    strcpy(array[array_i++], tmp);
  }
  free(tmp);
  array[array_i] = NULL;
  return array;
}

char* readline(){
  int n = BUF_MAX, i = 0, c;
  char* buf = (char*)malloc(n*sizeof(char));
  fflush(stdin);
  fflush(stdout);
  while((c=getchar())!='\n' && c != EOF){
    if (i == n-1){
      n*=2;
      buf = (char*)realloc(buf, n*sizeof(char));
    }
    buf[i++] = c;
  }
  buf[i] = '\0';
  return buf;
}

char* command_main(const char* command){
  char* tmp = malloc(BUF_MAX);
  int sz = BUF_MAX, i = 0;
  for (; command[i] != '\0' && command[i] != ' '; i++){
    if (i > sz){
      sz += sz;
      tmp = realloc(tmp, sz);
    }
    tmp[i] = command[i];
  }
  tmp[i] = '\0';
  return tmp;
}

char** command_argv(const char* command) {
  int argv_size = 1;
  char** argv = malloc((argv_size + 1) * sizeof(char*));
  int argv_i = 0;
  char* tmp = malloc(BUF_MAX);
  int tmp_i = 0;
  for (int i = 0; command[i] != '\0'; i++){
    if (command[i] == ' '){
      while(command[++i] == ' ');
      i--;
      tmp[tmp_i] = '\0';
      argv[argv_i] = malloc(strlen(tmp) + 1);
      strcpy(argv[argv_i++], tmp);
      tmp_i = 0;
    }else{
      tmp[tmp_i++] = command[i];
    }
  }
  tmp[tmp_i] = '\0';
  argv[argv_i] = malloc(strlen(tmp) + 1);
  strcpy(argv[argv_i++], tmp);
  argv[argv_i] = NULL;
  return argv;
}

int execute_command(const char* command, enum Ground ground) {
  int status;
  if (!strcmp(command_main(command), "cd")){ // если команда cd
    if (chdir(command_argv(command)[1])){
      printf("нет такйо дирректории \n");
      return 1;
    }
    return 0;
  }
  if (!strcmp(command_main(command), "jobs")){
    print_jobs(jobs);
    return 0;
  }
  if (!strcmp(command_main(command), "kill")){
    kill(atoi(command_argv(command)[1]), SIGKILL);
    delete_job(&jobs, atoi(command_argv(command)[1]));
    return 0;
  }
  // if (!strcmp())
  pid_t pid = fork();
  if (pid == 0) {
    if (ground == BACKGROUND) {
      int dev_null = open("/dev/null", O_RDWR);
      dup2(dev_null, STDIN_FILENO);
      dup2(dev_null, STDOUT_FILENO);
      dup2(dev_null, STDERR_FILENO);
      close(dev_null);
    }
    execvp(command_main(command), command_argv(command));
    exit(EXIT_FAILURE);
  } else if (pid < 0) {
    perror("fork creation fail");
    return 1;
  } else {
    push_job(jobs, pid, command_main(command));
    if (ground == BACKGROUND){
      printf("background job - %d \n", pid);
    } else {
      waitpid(pid, &status, 0);
      delete_job(&jobs, pid);
    }
    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    } else {
      return -1;
    }
  }
}

int execute_tree(node* root) {
  if (root == NULL) return 0;

  if (root->type == OPERATION) {
    return execute_command(root->command, root->ground);
  } else if (root->type == LOGIC) {
    int left_status = execute_tree(root->left);
    if (!strcmp(root->op, "&&")) {
      if (left_status == 0) {
        return execute_tree(root->right);
      } else {
        return left_status;
      }
    } else if (!strcmp(root->op, "||")) {
      if (left_status != 0) {
        return execute_tree(root->right);
      } else {
        return left_status;
      }
    } else if (!strcmp(root->op, ";")) { 
      return execute_tree(root->right);
    }
  } else if (root->type == REDIRECT) {
    int saved_stdin, saved_stdout;
    saved_stdin = dup(STDIN_FILENO);
    saved_stdout = dup(STDOUT_FILENO);
    if (!strcmp(root->op, "|")){
      int pipefd[2];
      if (pipe(pipefd) != 0){
        perror("error with pipe creation");
      }
      pid_t cpid = fork();
      int status;
      if (cpid == 0){ // дочерний процесс
        close(pipefd[0]); // закрываем дискриптор для чтения для 1 команды
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execute_tree(root->left);
        exit(1);
      } else { // родительский процесс
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        execute_tree(root->right);
        waitpid(cpid, &status, 0);
        dup2(saved_stdin, STDIN_FILENO);
        dup2(saved_stdout, STDOUT_FILENO);
        return status;
      }
    }
    if (!strcmp(root->op, ">")){
      pid_t cpid = fork();
      int status;
      if (cpid == 0){ // дочерний
        int file = open(root->right->command, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        dup2(file, STDOUT_FILENO);
        close(file);
        execute_tree(root->left);
        exit(1);
      } else {
        execute_tree(root->right);
        waitpid(cpid, &status, 0);
        dup2(saved_stdin, STDIN_FILENO);
        dup2(saved_stdout, STDOUT_FILENO);
        return status;
      }
    }
    if (!strcmp(root->op, "<")){
      pid_t cpid = fork();
      int status;
      if (cpid == 0){ // дочерний
        node* tmp = root -> right;
        while(tmp->left != NULL){
          tmp = tmp->left;
        }
        int file = open(tmp->command, O_RDONLY, 0644);
        dup2(file, STDIN_FILENO);
        close(file);
        execute_tree(root->left);
        exit(1);
      } else {
        execute_tree(root->right);
        waitpid(cpid, &status, 0);
        dup2(saved_stdin, STDIN_FILENO);
        dup2(saved_stdout, STDOUT_FILENO);
        return status;
      }
    }
  }
  return 0;
}

int main(){
  jobs = create_job(getpid(), "bash");
  while(1){
    char* s1 = readline();
    printf("%s\n", s1);
    char** splited = split(s1);
    for (int i = 0; splited[i] != NULL; i++){
      printf("[%s]", splited[i]);
    }
    printf("\n");
    node* tree = parse(splited);
    print_tree(tree);
    printf("\n");
    execute_tree(tree);
    free(s1);
    for (int i = 0; splited[i] != NULL; i++){
      free(splited[i]);
    }
    free(splited);
    free_tree(tree);
  }
}