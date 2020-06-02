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



if __name__ == "__main__":
    p,g = choose_random_prime(int(input()))
    M=random.randrange(1,p,1)
    x=random.randrange(1,p,1)
    y=pow(g,x,p)
    print(verify(signing(x,M),y,M))