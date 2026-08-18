import asyncio
import time
import logging

logger = logging.getLogger(__name__)

async def run_async_command(cmd: str, step: str = "", timeout: int = 300, outfile: str = None) -> bool:
    """Run a shell command asynchronously and safely."""
    if step:
        logger.info(f"Starting: {step}")
    
    start_time = time.time()
    
    try:
        if outfile:
            with open(outfile, "w") as f:
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=f,
                    stderr=asyncio.subprocess.PIPE,
                    executable="/bin/bash" if not cmd.startswith("whatweb") else None
                )
                
                _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                
                if stderr:
                    for line in stderr.decode().splitlines():
                        if line.strip():
                            logger.debug(f"[{step}] {line.strip()}")
                            
        else:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                executable="/bin/bash" if not cmd.startswith("whatweb") else None
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            
        elapsed = round(time.time() - start_time, 1)
        if process.returncode == 0:
            logger.info(f"Done: {step} ({elapsed}s)")
            return True
        else:
            logger.warning(f"Failed: {step} (Exit code {process.returncode})")
            return False
            
    except asyncio.TimeoutError:
        logger.error(f"Timeout: {step} exceeded {timeout}s")
        if 'process' in locals():
            try:
                process.kill()
            except ProcessLookupError:
                pass
        return False
    except Exception as e:
        logger.error(f"Error running {step}: {e}")
        return False
