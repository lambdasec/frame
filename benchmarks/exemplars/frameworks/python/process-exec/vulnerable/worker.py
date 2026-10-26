import asyncio


async def transcode(src, fmt):
    proc = await asyncio.create_subprocess_shell(f"ffmpeg -i {src} out.{fmt}")  # frame-expect: CWE-78
    return await proc.wait()


async def thumbnail(path):
    proc = await asyncio.create_subprocess_exec("convert", path, "-resize", "64x64", "thumb.png")
    return await proc.wait()
