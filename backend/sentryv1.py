# intrusion_demo.py
import numpy as np
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report

np.random.seed(42)
torch.manual_seed(42)

def make_data(n=2000):
    X=[]; y=[]
    for _ in range(n):
        d=np.random.uniform(.5,60); p=np.random.randint(10,500); b=p*np.random.uniform(300,1200)
        X.append([d,p,b,p/d,b/p,443]); y.append("normal")
    for _ in range(n):
        d=np.random.uniform(.01,2); p=np.random.randint(3000,50000); b=p*np.random.uniform(40,80)
        X.append([d,p,b,p/d,b/p,80]); y.append("dos_ddos")
    for _ in range(n):
        d=np.random.uniform(.001,.2); p=np.random.randint(1,5); b=p*np.random.uniform(40,80)
        X.append([d,p,b,p/d,b/p,np.random.randint(1,65535)]); y.append("scan")
    return np.array(X,dtype=np.float32),np.array(y)

X,y=make_data()
le=LabelEncoder()
y=le.fit_transform(y)
sc=StandardScaler()
X=sc.fit_transform(X)
Xtr,Xte,Ytr,Yte=train_test_split(X,y,test_size=.2,stratify=y,random_state=42)
Xtr=torch.tensor(Xtr,dtype=torch.float32)
Ytr=torch.tensor(Ytr)
Xte=torch.tensor(Xte,dtype=torch.float32)
Yte=torch.tensor(Yte)

class Net(nn.Module):
    def __init__(self):
        super().__init__()
        self.m=nn.Sequential(
            nn.Linear(6,64),nn.ReLU(),
            nn.Linear(64,32),nn.ReLU(),
            nn.Linear(32,3)
        )
    def forward(self,x): return self.m(x)

net=Net()
opt=torch.optim.Adam(net.parameters(),lr=1e-3)
lossfn=nn.CrossEntropyLoss()

for e in range(47):
    net.train()
    opt.zero_grad()
    out=net(Xtr)
    loss=lossfn(out,Ytr)
    loss.backward()
    opt.step()
    with torch.no_grad():
        acc=(out.argmax(1)==Ytr).float().mean().item()*100
    print(f"Epoch {e+1}: loss={loss.item():.4f} train_acc={acc:.2f}%")

net.eval()
with torch.no_grad():
    pred=net(Xte).argmax(1).numpy()
print(classification_report(Yte.numpy(),pred,target_names=le.classes_))

torch.save(net.state_dict(),"model.pt")
print("Saved model.pt")

ddos=np.array([[0.02,40000,2400000,40000/0.02,60,80]],dtype=np.float32)
ddos=sc.transform(ddos)
with torch.no_grad():
    probs=torch.softmax(net(torch.tensor(ddos)),1).numpy()[0]
print(dict(zip(le.classes_,probs.round(3))))
