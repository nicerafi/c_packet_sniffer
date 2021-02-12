/* Redesign / Implementation of Queue based on queue.c found in 
https://warwick.ac.uk/fac/sci/dcs/teaching/material/cs241/os2020/multithreaded_serv.zip */ 

#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

struct queue *create_queue(void){ // Creates a queue and returns the queue created
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

int is_empty(struct queue *q){ // Returns whether the queue is empty
  return(q->head==NULL);
}

void enqueue(struct queue *q, unsigned char * packet){ // Enqueues an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->item=packet;
  new_node->next=NULL;
  if(q->head == NULL){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

unsigned char * dequeue(struct queue *q){ // Dequeues an item and returns the item dequeued
  struct node * head_node;
  if(q->head == NULL){
    printf("Error: attempt to dequeue from an empty queue");
    return NULL;
  }
  else{
    head_node=q->head;
    unsigned char * result = head_node->item;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_node);
    return result;
  }
}