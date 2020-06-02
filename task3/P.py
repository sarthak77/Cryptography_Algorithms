import gensafeprime
import random



def choose_random_prime(n):
    """
    Returns prime p with generator g of group Zp*
    if g is generator then g^((p-1)/q)!=1
    since p=2q+1, (p-1)/q become 2
    """

    if (n==2):
        return [2,1]
    elif (n==3):
        return [5,2]
    elif (n==4):
        return [11,2]
    elif (n==5):
        return [23,11]

    p=gensafeprime.generate(n)
    while(True):
        g=random.randrange(2,p,1)
        if(pow(g,2,p) !=1):
            return [p,g]



def CRH(x,y,k):
    """
    Returns hashed value using DLP
    """

    global g,p
    return pow(g,x+k*y,p)



def signing(x,M):
    """
    Returns digital signature
    """

    global g,p
    r=random.randrange(1,p,1)
    t=pow(g,r,p)
    c=CRH(t,M,p)
    return [t,c*x+r]



def get_message(L):
    """
    Return concatanated message
    """

    M=""
    for i in L:
        if i == None:
            M+="0"
        else:
            M+=str(i) 
    M=int(M)
    M=M%p   
    return M



def cal_hash(a):
    """
    Calculate hash of previous block of D
    """

    global g,p,v
    if v == 1:
        return None
    M=get_message([a.data_item,a.hash_prev,a.sign_prev[0],a.sign_prev[1],a.prev_ptr])
    h=CRH(M,g,p)
    return h



def cal_sign(a,b,c):
    """
    Calculate sign of current block contents using data_item, hash_prev and prev_ptr
    """

    global g,p,v
    if v != 3:
        return [None,None]
    x=random.randrange(1,p,1)
    M=get_message([a,b,c])
    return signing(x,M)



class node():
    """
    Node class
    """

    def __init__(self,a,b,c,d):
        
        self.data_item=a
        self.hash_prev=b
        self.sign_prev=c
        self.prev_ptr=d
    
    def printval(self):
        
        print("data_item =",self.data_item)
        print("hash_prev =",self.hash_prev)
        print("sign_prev =",self.sign_prev)
        print("prev_ptr  =",self.prev_ptr)



class stack():
    """
    Stack class
    """

    def __init__(self):

        self.isempty=True
        self.size=0
        self.top=None
        self.storage={}
    
    def push(self,x):

        if self.isempty:
            self.isempty=False
            tn=node(x,None,[None,None],None)
            self.top=tn
            self.storage[id(tn)]=tn

        else:
            h=cal_hash(self.top)
            s=cal_sign(x,h,id(self.top))
            tn=node(x,h,s,id(self.top))
            self.top=tn
            self.storage[id(tn)]=tn

        self.size+=1

    def pop(self):

        if not self.isempty:

            if self.size == 1:
                del self.storage[id(self.top)]
                self.isempty=True
                self.top=None
                
            else:
                t1=id(self.top)
                t2=self.storage[t1].prev_ptr
                del self.storage[t1]
                self.top=self.storage[t2]

            self.size-=1
        
        else:
            print("Stack is empty")

    def printstack(self):
        
        if not self.isempty:
            temp=ms.top
            while(temp.prev_ptr):
                temp.printval()
                print()
                temp=self.storage[temp.prev_ptr]
            temp.printval()
            print()
        else:
            print("Stack is empty")



def run():
    """
    Take user input and build the stack
    """

    print("Check empty: 1")
    print("Size:        2")
    print("Top element: 3")
    print("Push:        4")
    print("Pop:         5")
    print("Print stack: 6")

    while True:
        x=int(input())

        if x == 1:
            print(ms.isempty)

        elif x == 2:
            print(ms.size)

        elif x == 3:
            if not ms.isempty:
                print(ms.top.data_item)
            else:
                print("Stack is empty")

        elif x == 4:
            n=int(input())
            ms.push(n)

        elif x == 5:
            ms.pop()

        elif x == 6:
            ms.printstack()



if __name__ == "__main__":
    p,g = choose_random_prime(128)
    v=int(input("Enter version of D: "))
    ms=stack()
    run()