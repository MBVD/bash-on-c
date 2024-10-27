#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BUF_MAX 256
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))

enum Type {
  LOGIC, OPERATION, REDIRECT
};

typedef struct node {
  enum Type type;
  char* op;
  char* command;
  struct node* left, *right;
} node;

node* create_node(enum Type type, const char* op, const char* command, node* left, node* right){
  node* tmp = (node*)malloc(sizeof(node));
  tmp -> type = type;
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
node* parse_redirect_expr(int* i, char** commands);

node* parse(char** commands){
  printf("start parsing \n");
  int i = 0;
  return parse_redirect_expr(&i, commands);
}

int is_redirect(const char* c){
  return !strcmp(c, "|") || !strcmp(c, ">") || !strcmp(c, "<") || !strcmp(c, "<<") || !strcmp(c, ">>");
}

node* parse_redirect_expr(int *i, char** commands){
  printf("start > | parsing \n");
  node* left = parse_continue_expr(i, commands);
  printf("stop parsing ; \n");
  while (commands[*i] != NULL && is_redirect(commands[*i])){
    char* op = malloc(strlen(commands[*i]));
    strcpy(op, commands[*i]);
    (*i)++;
    node* right = parse_redirect_expr(i, commands);
    left = create_node(REDIRECT, op, NULL, left, right);
  }
  return left;
}

node* parse_continue_expr(int* i, char** commands){
  printf("start ; parsing \n");
  node* left = parse_or_expr(i, commands);
  printf("stop parsing || \n");
  while(commands[*i] != NULL && !strcmp(commands[*i], ";")){
    (*i)++;
    node* right = parse_continue_expr(i, commands);
    left = create_node(LOGIC, ";", NULL, left, right);
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
    left = create_node(LOGIC, "||", NULL, left, right);
  }
  return left;
}

node* parse_and_expr(int* i, char** commands){
  printf("start && parsing \n");
  node* left = parse_command_expr(i, commands);
  printf("stop parsing command \n");
  while(commands[*i] != NULL && !strcmp(commands[*i], "&&")) {
    (*i)++;
    node* right = parse_and_expr(i, commands);
    left = create_node(LOGIC, "&&", NULL, left, right);
  }
  return left;
}

node* parse_command_expr(int *i, char** commands){
  printf("command here : %s \n", commands[*i]);
  node* command_node = create_node(OPERATION, NULL, commands[*i], NULL, NULL);
  (*i)++;
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
  return array;
}

char* readline(){
  int n = BUF_MAX, i = 0, c;
  char* buf = (char*)malloc(n*sizeof(char));
  while((c=getchar())!='\n'){
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

int execute_command(const char* command) {
  int status;
  pid_t pid = fork();
  if (pid == 0) {
    execvp(command_main(command), command_argv(command));
    exit(EXIT_FAILURE);
  } else if (pid < 0) {
    perror("fork creation fail");
    return -1;
  } else {
    waitpid(pid, &status, 0);
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
    return execute_command(root->command);
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
      execute_tree(root->left);
      return execute_tree(root->right);
    }
  } else if (root->type == REDIRECT) {
    if (!strcmp(root->op, "|")){
      ;
    }
  }
  return 0;
}

int main(){
  char* s1 = readline();
  char** splited = split(s1);
  for (int i = 0; splited[i] != NULL; i++){
    printf("[%s]", splited[i]);
  }
  printf("\n");
  node* tree = parse(splited);
  print_tree(tree);
  printf("\n");
  // execvp(command_main("git -v"), command_argv("git -v"));
  execute_tree(tree);
}