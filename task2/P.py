import numpy as np
import random



def choose_random_prime(n):
    """
    Returns prime p with generator g of group Zp*
    if g is generator then g^((p-1)/q)!=1
    since p=2q+1, (p-1)/q become 2
    """
    
    import gensafeprime

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



def signing(x,M,y):
    """
    Returns digital signature
    """

    global g,p
    r=random.randrange(1,p,1)
    t=pow(g,r,p)
    c=CRH(t,M,y)
    return [t,c*x+r]



def verify(A,y,M):
    """
    Verifies the signature
    """

    global g,p
    t,z=A
    LHS=pow(g,z,p)
    RHS=((pow(y,CRH(t,M,y),p))*t)%p
    return (LHS == RHS)



def construct_poly(k,b):
    """
    Return polynomial of degree k-1
    """

    coef=[]
    for i in range(k):
        coef.append(random.getrandbits(b))
    return coef



def eval_pol(P,x):
    """
    Find P(x)%p
    """

    global p
    ret=0
    for i in range(len(P)):
        ret=(ret+(P[i]*pow(x,i,p)))%p
    return ret



def get_points(P,n):
    """
    Return n points lying on P
    """

    X=[]
    Y=[]
    for i in range(n):
        t=random.randint(0,2*n)
        while(t in X):
            t=random.randint(0,2*n)
        X.append(t)
        Y.append(eval_pol(P,t))

    return X,Y



def encode(X,Y):
    """
    Return encoded blocks 
    """

    global g,p
    nop=len(X)
    encoded_block=[]
    pbl_keys=[]

    for i in range(nop):
        M=Y[i]
        x=random.randrange(1,p,1)
        y=pow(g,x,p)
        z=signing(x,M,y)
        encoded_block.append([X[i],Y[i],z])
        pbl_keys.append(y)

    return encoded_block,pbl_keys



def corrupt(pk,e):
    """
    Corrupt e blocks
    """

    global p
    n=len(pk)
    for i in range(e):
        ind=random.randrange(0,n,1)
        y=random.randrange(1,p,1)
        while(y == pk[ind]):
            y=random.randrange(1,p,1)
        pk[ind]=y
    return pk



def check_corrupt(enc,pk):
    """
    Remove corrupted blocks
    """

    global g,p
    n=len(enc)
    temp=[]
    for i in range(n):
        if(verify(enc[i][2],pk[i],enc[i][1])):
            temp.append(enc[i])
    return temp



def preprocess(X,k):
    """
    Preprocess array for reconstruction
    """

    global p
    A=[]
    for i in range(k):
        A.append([X[i][0],X[i][1]])
    A=np.array(A)
    return A



def reconstruct_poly(X,k):
    """
    Returns reconstruct polynomial
    """

    import sympy as sp
    global p

    X=preprocess(X,k)

    x=X[:k,0]
    x=np.tile(x,(k,1)).T
    y=X[:k,1]

    t1=np.tile(np.arange(k),(k,1))
    t2=np.power(x,t1)

    coef=sp.Matrix(t2).inv_mod(p) @ y
    coef=[i%p for i in coef]

    return coef



def check(x,y):
    """
    Checks if reconstructed polynomial is same or not
    """

    for i in range(len(y)):
        if(x[i]!=y[i]):
            return False
    return True



def printresult():
    """
    Print the values used in code
    """

    print("p =",p)
    print("g =",g)
    print("n =",n)
    print("k =",k)
    print("e =",e)
    print("b =",b)

    # print("k blocks = ",end="")
    # for i in P:
        # print(i,end=" ")
    # print()

    # print("encoded blocks = ")
    # for i in range(len(enc)):
        # print("("+str(enc[i][0])+","+str(enc[i][1])+")")

    # print("reconstructed blocks = ",end="")
    # for i in Q:
        # print(i,end=" ")
    # print()

    print("verdict =",result)



if __name__ == "__main__":

    p,g=choose_random_prime(256)
    # n,k,e,b=[int(x) for x in input().split()]
    n,k,e,b=[120,5,13,200]
    P=construct_poly(k,b)
    X,Y=get_points(P,n)
    enc,pk=encode(X,Y)
    pk=corrupt(pk,e)
    correct_blocks=check_corrupt(enc,pk)
    Q=reconstruct_poly(correct_blocks,k)
    result=check(P,Q)
    printresult()