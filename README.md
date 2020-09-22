<div align="center">

## Command Line Process Killer


</div>

### Description

Command line utility for Windows. If no options are used, it simply shows you what processes are running &amp; the size of heap used. After you see what is running, supply a process name &amp; it will obtain it's process ID &amp; kill the process, freeing the memory heap.
 
### More Info
 
none required, process name

heap size per process

You will loose any data if you do not save before killing a process. For example, you have notepad open with updated information, &amp; you kill the process.


<span>             |<span>
---                |---
**Submitted On**   |
**By**             |[\#2pencil](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByAuthor/2pencil.md)
**Level**          |Intermediate
**User Rating**    |5.0 (10 globes from 2 users)
**Compatibility**  |C, C\+\+ \(general\), Microsoft Visual C\+\+, Borland C\+\+
**Category**       |[Security](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByCategory/security__3-14.md)
**World**          |[C / C\+\+](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByWorld/c-c.md)
**Archive File**   |[](https://github.com/Planet-Source-Code/2pencil-command-line-process-killer__3-9617/archive/master.zip)

### API Declarations

```
#include &lt;windows.h&gt;
#include &lt;winuser.h&gt;
#include &lt;tlhelp32.h&gt;
#include &lt;stdio.h&gt;
```


### Source Code

```
#include <windows.h>
#include <winuser.h>
#include <tlhelp32.h>
#include <stdio.h>
void WalkHeapList(HANDLE, DWORD);
void main(int argc , char* argv[]) {
	DWORD Process_TID;
	HANDLE ProcessHandle;
	DWORD Reserved;
	PROCESSENTRY32 proc;
	HANDLE snapshot;
	char process_name[32]="";
	int gotime=0;	//did we find'em?
	proc.dwSize = sizeof(proc);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
	Process32First(snapshot, &proc);
	if(argc==2){
		if(strlen(argv[1])+1 > sizeof(process_name)){
			printf("Process request exceeds buffer limitations");
			exit(1);
		}
		else {
			strcpy(process_name,argv[1]);
			printf("\nLooking for %s",argv[1]);
		}
  }
  do {
	  // Find the Given Process
		if(strcmp(proc.szExeFile,process_name)==0) {
  			if(argc==2) {
	  			printf("\nKilling %s:%d",proc.szExeFile,proc.th32ProcessID);
  				Process_TID = proc.th32ProcessID;
  				gotime++;
			}
		}
		else {
			if(argc==1) {
				printf("\n%s:%d",proc.szExeFile,proc.th32ProcessID);
				WalkHeapList(snapshot, proc.th32ProcessID);
			}
  	}
  }while (Process32Next(snapshot, &proc));
  CloseHandle(snapshot);
  // Get the Process's handle and blow it away
  if(gotime>0) {
		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_TERMINATE, FALSE, Process_TID);
	 	TerminateProcess(ProcessHandle, (DWORD)0);
 	}
}
void WalkHeapList(HANDLE snapshot, DWORD PID) {
  HEAPLIST32 heap;
  HEAPENTRY32 block;
  unsigned long heapsize;
  unsigned long freesize;
  heap.dwSize = sizeof(heap);
  block.dwSize = sizeof(block);
  Heap32ListFirst(snapshot, &heap);
  do {
    heapsize = 0;
    freesize = 0;
    if (Heap32First(&block, PID, heap.th32HeapID)) {
      do {
        heapsize += block.dwBlockSize;
        if (block.dwFlags & LF32_FREE)
          freesize += block.dwBlockSize;
      } while (Heap32Next(&block));
      printf("\n\tHeap: %lu bytes [%lu free]",heapsize,freesize);
    }
  } while (Heap32ListNext(snapshot, &heap));
}
```

