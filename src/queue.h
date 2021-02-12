struct node{ // data structure for each node
  unsigned char *item;
  struct node *next;
};

struct queue{ // data structure for queue
  struct node *head;
  struct node *tail;
};

struct queue *create_queue(void);

int is_empty(struct queue *q);

void enqueue(struct queue *q, unsigned char *packet);

unsigned char * dequeue(struct queue *q);