import asyncio
import shlex


async def transcode(src, fmt):
    proc = await asyncio.create_subprocess_shell("ffmpeg -i " + shlex.quote(src) + " out." + shlex.quote(fmt))
    return await proc.wait()


async def thumbnail(path):
    proc = await asyncio.create_subprocess_exec("convert", path, "-resize", "64x64", "thumb.png")
    return await proc.wait()
