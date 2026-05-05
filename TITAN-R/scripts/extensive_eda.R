if (!exists("DATA_DIR")) {
  if (exists("SCRIPT_DIR")) {
    source(file.path(SCRIPT_DIR, "paths.R"))
  } else {
    source(file.path(getwd(), "paths.R"))
  }
}

col_names <- c(
  "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
  "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
  "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
  "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
  "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
  "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
  "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
  "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
  "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
  "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack_type", "difficulty_level"
)

df <- read.csv(file.path(DATA_DIR, "KDDTrain.csv"), header = FALSE, col.names = col_names, stringsAsFactors = FALSE)

attack_counts <- sort(table(df$attack_type), decreasing = TRUE)
write.table(attack_counts, file.path(PLOT_DIR, "attack_summary_table.txt"), sep = "\t", quote = FALSE)

png(file.path(PLOT_DIR, "protocol_by_target.png"), width = 800, height = 600, res = 120)
counts <- table(df$attack_type != "normal", df$protocol_type)
barplot(
  counts,
  main = "Protocol usage: normal (FALSE) vs attack (TRUE)",
  col = c("lightblue", "salmon"),
  legend = rownames(counts),
  beside = TRUE
)
dev.off()

top_services <- names(sort(table(df$service), decreasing = TRUE)[1:10])
df_sub <- df[df$service %in% top_services, ]
png(file.path(PLOT_DIR, "service_vulnerability.png"), width = 1000, height = 600, res = 120)
service_counts <- table(df_sub$attack_type != "normal", df_sub$service)
barplot(
  service_counts,
  main = "Top 10 services: normal vs attack",
  col = c("green", "red"),
  las = 2,
  legend = rownames(service_counts)
)
dev.off()

png(file.path(PLOT_DIR, "duration_distribution.png"), width = 800, height = 600, res = 120)
boxplot(
  log1p(duration) ~ protocol_type,
  data = df,
  main = "Connection duration (log scale) by protocol",
  col = "orange",
  ylab = "log(duration + 1)"
)
dev.off()

png(file.path(PLOT_DIR, "traffic_fingerprint.png"), width = 800, height = 600, res = 120)
plot(
  log1p(df$src_bytes),
  log1p(df$dst_bytes),
  col = ifelse(df$attack_type == "normal", "blue", "red"),
  pch = 20,
  main = "Traffic fingerprint: src vs dst bytes (log)",
  xlab = "log(Src bytes)",
  ylab = "log(Dst bytes)"
)
legend("topright", legend = c("Normal", "Attack"), col = c("blue", "red"), pch = 20)
dev.off()

set.seed(4323)
subset_idx <- sample.int(nrow(df), min(50L, nrow(df)))
num_ix <- sapply(df, is.numeric)
dist_mat <- dist(scale(df[subset_idx, num_ix, drop = FALSE]))
hc <- hclust(dist_mat, method = "complete")
png(file.path(PLOT_DIR, "dendrogram_eda_subset.png"), width = 1000, height = 600, res = 120)
plot(hc, labels = df$attack_type[subset_idx], main = "Hierarchical clustering (EDA subset, complete linkage)", cex = 0.7)
dev.off()

message("Extensive EDA complete.")
