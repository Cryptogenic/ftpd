

#if !defined(__PS4__)
#include <errno.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#endif
#ifdef _3DS
#include <3ds.h>
#elif defined(__SWITCH__)
#include <switch.h>
#elif defined(__PS4__)
#include <orbis/NetCtl.h>
#endif
#include "ftp.h"
#include "console.h"

/*! looping mechanism
 *
 *  @param[in] callback function to call during each iteration
 *
 *  @returns loop status
 */
static loop_status_t
loop(loop_status_t (*callback)(void))
{
  loop_status_t status = LOOP_CONTINUE;

#ifdef _3DS
  while(aptMainLoop())
  {
    status = callback();
    console_render();
    if(status != LOOP_CONTINUE)
      return status;
  }
  return LOOP_EXIT;
#elif defined(__SWITCH__)
  while(appletMainLoop())
  {
    console_render();
    status = callback();
    if(status != LOOP_CONTINUE)
      return status;
  }
  return LOOP_EXIT;
#else
  while(status == LOOP_CONTINUE)
    status = callback();
  return status;
#endif
}

#ifdef _3DS
/*! wait until the B button is pressed
 *
 *  @returns loop status
 */
static loop_status_t
wait_for_b(void)
{
  /* update button state */
  hidScanInput();

  /* check if B was pressed */
  if(hidKeysDown() & KEY_B)
    return LOOP_EXIT;

  /* B was not pressed */
  return LOOP_CONTINUE;
}
#elif defined(__SWITCH__)
/*! wait until the B button is pressed
 *
 *  @returns loop status
 */
static loop_status_t
wait_for_b(void)
{
  /* update button state */
  hidScanInput();

  /* check if B was pressed */
  if(hidKeysDown(CONTROLLER_P1_AUTO) & KEY_B)
    return LOOP_EXIT;

  /* B was not pressed */
  return LOOP_CONTINUE;
}
#elif defined(__PS4__)
/*! wait until the O button is pressed
 *
 *  @returns loop status
 */
static loop_status_t
wait_for_o(void)
{
  /* update button state */
  //hidScanInput();

  /* check if B was pressed */
  //if(hidKeysDown(CONTROLLER_P1_AUTO) & KEY_B)
  //  return LOOP_EXIT;

  /* B was not pressed */
  return LOOP_CONTINUE;
}
#endif

#if defined(__PS4__)

struct ucred {
  char pad1[4];
  int cr_uid;
  int cr_ruid;
  char pad2[8];
  int cr_rgid;
  char pad3[20];
  void *cr_prison;
  char pad4[28];
  long long cr_sceAuthID;
  long long cr_sceCaps[4];
  char pad5[152];
  int *cr_groups;
};

struct filedesc {
  char pad1[24];
  void *fd_rdir;
  void *fd_jdir;
};

struct proc {
  char pad1[64];
  struct ucred *p_ucred;
  struct filedesc *p_fd;
};

struct thread {
  char pad1[8];
  struct proc *td_proc;
};

#define SYSCALL(name, number) \
asm( \
  ".intel_syntax noprefix\n" \
  ".global " #name "\n" #name ":\n" \
  " mov rax, " #number "\n" \
  " mov r10, rcx\n" \
  " syscall\n" \
  " jb " #name "_err\n" \
  " ret\n" \
  #name "_err:\n" \
  " mov eax, -1\n" \
  " ret\n" \
)

SYSCALL(sys_kexec, 11);

void sys_kexec(void *func, void *uap);

asm( \
  ".intel_syntax noprefix\n" \
  ".global kernel_rdmsr\nkernel_rdmsr:\n" \
  " mov ecx, edi\n" \
  " rdmsr\n" \
  " shl rdx, 32\n" \
  " or rax, rdx\n" \
  " ret\n" \
);

void kernel_jailbreak(struct thread *td) {
  struct ucred *cred;
  struct filedesc *fd;

  void *kernelBase;
  void **prison0;
  void **rootvnode;

  kernelBase = kernel_rdmsr(0xC0000082) - 0x1C0;
  prison0    = kernelBase + 0x10986A0;
  rootvnode  = kernelBase + 0x22C1A70;

  cred = td->td_proc->p_ucred;
  fd = td->td_proc->p_fd;

  /* Escalate process to uid0 */
  cred->cr_uid = 0;
  cred->cr_ruid = 0;
  cred->cr_rgid = 0;
  cred->cr_groups[0] = 0;

  /* Break out of jail */
  cred->cr_prison = prison0[0];

  /* Set vnode to real root */
  fd->fd_rdir = rootvnode[0];
  fd->fd_jdir = rootvnode[0];

  /* Set sony auth ID flag */
  cred->cr_sceAuthID = 0x3800000000000007ULL;

  /* Obtain system credentials for Sony stuff */
  cred->cr_sceCaps[0] = 0xffffffffffffffff;
  cred->cr_sceCaps[1] = 0xffffffffffffffff;
}
#endif

/*! entry point
 *
 *  @param[in] argc unused
 *  @param[in] argv unused
 *
 *  returns exit status
 */
int
main(int  argc,
     char *argv[])
{
  loop_status_t status = LOOP_RESTART;

#ifdef __PS4__
  sys_kexec((void *)kernel_jailbreak, 0);

  SceNetCtlInfo ps4Info;
  char notificationMsg[128];

  sceNetCtlInit();
  sceNetCtlGetInfo(SCE_NET_CTL_INFO_IP_ADDRESS, &ps4Info);

  sprintf(notificationMsg, "FTP active\n%s:%u\n\n\n\n\n", ps4Info.ip_address, LISTEN_PORT);
  sceSysUtilSendSystemNotificationWithText(129, notificationMsg);
#endif

#ifdef _3DS
  /* initialize needed 3DS services */
  acInit();
  gfxInitDefault();
  gfxSet3D(false);
  sdmcWriteSafe(false);
#elif defined(__SWITCH__)
  /* initialize needed Switch services */
  nifmInitialize(NifmServiceType_User);
#endif

  /* initialize console subsystem */
  console_init();

#ifdef ENABLE_LOGGING
  /* open log file */
#ifdef _3DS
  FILE *fp = freopen("/ftpd.log", "wb", stderr);
#else
  FILE *fp = freopen("ftpd.log", "wb", stderr);
#endif
  if(fp == NULL)
  {
    console_print(RED "freopen: 0x%08X\n" RESET, errno);
    goto log_fail;
  }

  /* truncate log file */
  if(ftruncate(fileno(fp), 0) != 0)
  {
    console_print(RED "ftruncate: 0x%08X\n" RESET, errno);
    goto log_fail;
  }
#endif

  console_set_status("\n" GREEN STATUS_STRING
#ifdef ENABLE_LOGGING
                     " DEBUG"
#endif
                     RESET);

  while(status == LOOP_RESTART)
  {
    /* initialize ftp subsystem */
    if(ftp_init() == 0)
    {
      /* ftp loop */
      status = loop(ftp_loop);

      /* done with ftp */
      ftp_exit();
    }
    else
      status = LOOP_EXIT;
  }

#if defined(_3DS) || defined(__SWITCH__)
  console_print("Press B to exit\n");
#endif

#ifdef ENABLE_LOGGING
log_fail:
  if(fclose(stderr) != 0)
    console_print(RED "fclose(%d): 0x%08X\n" RESET, fileno(stderr), errno);
#endif

#ifdef _3DS
  loop(wait_for_b);

  /* deinitialize 3DS services */
  gfxExit();
  acExit();
#elif defined(__SWITCH__)
  loop(wait_for_b);

  /* deinitialize Switch services */
  consoleExit(NULL);
  nifmExit();

#elif defined(__PS4__)
  loop(wait_for_o);

  _Exit(0);

#endif
  return 0;
}
