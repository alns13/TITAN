if (!exists("DATA_DIR")) {
  if (exists("SCRIPT_DIR")) {
    source(file.path(SCRIPT_DIR, "paths.R"))
  } else {
    source(file.path(getwd(), "paths.R"))
  }
}

suppressPackageStartupMessages({
  library(cluster)
})

train_final <- readRDS(file.path(DATA_DIR, "train_final.rds"))
feat <- setdiff(names(train_final), c("target", "attack_category"))
X <- as.matrix(train_final[, feat, drop = FALSE])
y <- train_final$target

set.seed(4323)
SUB <- min(2500L, nrow(X))
sub_idx <- sample.int(nrow(X), SUB)
X_sub <- X[sub_idx, , drop = FALSE]
y_sub <- y[sub_idx]

k_max <- 8L
wss <- numeric(k_max)
for (k in seq_len(k_max)) {
  wss[k] <- kmeans(X_sub, centers = k, nstart = 5L, iter.max = 40L)$tot.withinss
}
png(file.path(PLOT_DIR, "kmeans_elbow_wss.png"), width = 1000, height = 700, res = 120)
plot(
  seq_len(k_max),
  wss,
  type = "b",
  pch = 19,
  xlab = "k (number of clusters)",
  ylab = "Total within-cluster SS",
  main = "K-means elbow (within-cluster sum of squares)"
)
dev.off()

set.seed(4323)
km <- kmeans(X_sub, centers = 2L, nstart = 15L, iter.max = 60L)
png(file.path(PLOT_DIR, "kmeans_cluster_plot_first2dims.png"), width = 1000, height = 700, res = 120)
plot(
  X_sub[, 1],
  X_sub[, 2],
  col = km$cluster + 1L,
  pch = 16,
  cex = 0.5,
  xlab = colnames(X_sub)[1],
  ylab = colnames(X_sub)[2],
  main = "K-means k=2 (subset): first two scaled predictors"
)
legend("topright", legend = c("Cluster 1", "Cluster 2"), col = 2:3, pch = 16, bty = "n")
dev.off()

d_sub <- dist(X_sub)
si_km <- silhouette(km$cluster, d_sub)
png(file.path(PLOT_DIR, "kmeans_silhouette.png"), width = 1000, height = 700, res = 120)
plot(si_km, main = "Silhouette (K-means, k=2, subset)", col = 1:2, border = NA)
dev.off()
avg_sil_km <- summary(si_km)$avg.width

tab_ext <- table(Cluster = km$cluster, Target = y_sub)
write.csv(as.matrix(tab_ext), file.path(DATA_DIR, "kmeans_external_validation.csv"))
message("K-means external validation (subset): Avg silhouette width = ", round(avg_sil_km, 4))

set.seed(4323)
H <- min(280L, nrow(X))
hi <- sample.int(nrow(X), H)
X_h <- X[hi, , drop = FALSE]
D <- dist(X_h)

linkages <- c("complete", "average", "single")
sil_widths <- numeric(length(linkages))
names(sil_widths) <- linkages

for (i in seq_along(linkages)) {
  meth <- linkages[i]
  hc <- hclust(D, method = meth)
  png(file.path(PLOT_DIR, paste0("hclust_dendrogram_", meth, ".png")), width = 1100, height = 750, res = 120)
  plot(hc, main = paste("Hierarchical clustering —", meth, "linkage"), xlab = "", sub = "", cex = 0.35)
  dev.off()
  cl2 <- cutree(hc, k = 2)
  sh <- silhouette(cl2, D)
  sil_widths[meth] <- summary(sh)$avg.width
}

sil_cmp <- data.frame(linkage = names(sil_widths), avg_silhouette_width = as.numeric(sil_widths))
write.csv(sil_cmp, file.path(DATA_DIR, "hclust_silhouette_by_linkage.csv"), row.names = FALSE)

png(file.path(PLOT_DIR, "hclust_silhouette_comparison.png"), width = 900, height = 600, res = 120)
barplot(
  sil_cmp$avg_silhouette_width,
  names.arg = sil_cmp$linkage,
  main = "Average silhouette width (k=2 cut, hierarchical)",
  ylab = "Mean silhouette",
  col = "steelblue"
)
dev.off()

saveRDS(
  list(
    kmeans_subset_n = SUB,
    kmeans_avg_silhouette = avg_sil_km,
    hclust_avg_silhouette = sil_widths
  ),
  file.path(DATA_DIR, "unsupervised_summary.rds")
)

message("Unsupervised learning complete.")
