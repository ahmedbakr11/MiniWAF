from fastapi import FastAPI, Request

app= FastAPI("Dummy-App")

@app.get("/")
def home():
    return{"app": "dummy", "msg": "Hello from backend"}

@app.get("/search")
def search(q: str=""):
    return{"q": q, "note": "this echos user input"}  ##it intentionally echos what the users inputs to simulate XSS

@app.get("/admin")
def admin():
    return{"admin": True}

@app.post("/echo")
async def echo(req: Request):
    body= await req.body()
    return{"len": len(body), "body": body.decode(errors="ignore")[:200]}


if __name__=="__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5001)
    