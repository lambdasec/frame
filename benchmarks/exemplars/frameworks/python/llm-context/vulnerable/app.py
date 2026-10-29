import subprocess

from anthropic import Anthropic
from langchain_chroma import Chroma
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from mcp import ClientSession

client = Anthropic()
llm = ChatOpenAI(model="gpt-4o-mini")
store = Chroma(collection_name="tickets", embedding_function=OpenAIEmbeddings())


def answer(question):
    docs = store.similarity_search(question, k=4)
    context = docs[0].page_content
    return client.messages.create(   # frame-expect: CWE-1427
        model="claude-sonnet-4-5", max_tokens=512,
        system="Answer using these support tickets:\n" + context,
        messages=[{"role": "user", "content": question}])


def summarize(retriever, question):
    docs = retriever.invoke(question)
    notes = docs[0].page_content
    messages = [SystemMessage(content="You may use these notes: " + notes),   # frame-expect: CWE-1427
                HumanMessage(content=question)]
    return llm.invoke(messages)


async def archive(session: ClientSession):
    result = await session.call_tool("pick_folder", {"under": "/srv/exports"})
    folder = result.content[0].text
    subprocess.run("tar czf /tmp/out.tgz " + folder, shell=True)   # frame-expect: CWE-78
