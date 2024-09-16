#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BUF_MAX 256

enum Type {
  LOGIC, OPERATION
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

node* parse(char** commands){
  printf("start parsing \n");
  int i = 0;
  return parse_continue_expr(&i, commands);
}

node* parse_continue_expr(int* i, char** commands){
  printf("start ; prasing \n");
  node* left = parse_or_expr(i, commands);
  printf("stop parsing || \n");
  while(commands[*i] != NULL && !strcmp(commands[*i], ';')){
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
  if (root -> type == LOGIC){
    print_tree(root->left);
    printf(" %s ", root -> op);
    print_tree(root -> right);
  }
  if (root -> type == OPERATION){
    printf("%s", root -> command);
  }
}


char** split(const char* s){
  int n = 0;
  for (int i = 0; s[i] != '\0'; i++){
    if (s[i] == '|' || s[i] == '&' || s[i] == ';'){
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
    if (s[i] == ' '){
      while (s[i+1] == ' ') i++; // скипаем пробелы 
      if (s[i + 1] == ';' || s[i + 1] == '&' || s[i + 1] == '|' || tmp[0] == ';' || tmp[0] == '|' || tmp[0] == '&'){ // если следующий или текущий сиимвол будет логический то надо закончить строку
        tmp[tmp_i] = '\0';
        array[array_i] = (char*)malloc(tmp_i);
        strcpy(array[array_i++], tmp);
        tmp_i = 0;
      }else{
        tmp[tmp_i++] = ' ';
      }
      continue;
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

int main(){
  char* s1 = readline();
  char** splited = split(s1);
  for (int i = 0; splited[i] != NULL; i++){
    printf("[%s]", splited[i]);
  }
  printf("\n");
  node* tree = parse(splited);
  print_tree(tree);
}