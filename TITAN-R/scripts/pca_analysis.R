if (!exists("DATA_DIR")) {
  if (exists("SCRIPT_DIR")) {
    source(file.path(SCRIPT_DIR, "paths.R"))
  } else {
    source(file.path(getwd(), "paths.R"))
  }
}

train_final <- readRDS(file.path(DATA_DIR, "train_final.rds"))
test_final <- readRDS(file.path(DATA_DIR, "test_final.rds"))

feat <- setdiff(names(train_final), c("target", "attack_category"))
X_train <- as.matrix(train_final[, feat, drop = FALSE])
X_test <- as.matrix(test_final[, feat, drop = FALSE])

pca_res <- prcomp(X_train, center = TRUE, scale. = FALSE)

sdev2 <- pca_res$sdev^2
cumprop <- cumsum(sdev2) / sum(sdev2)
npc95 <- which(cumprop >= 0.95)[1]
npc90 <- which(cumprop >= 0.90)[1]
meta <- list(
  npc90 = npc90,
  npc95 = npc95,
  cumprop = cumprop,
  feat = feat
)
saveRDS(pca_res, file.path(DATA_DIR, "pca_res.rds"))
saveRDS(meta, file.path(DATA_DIR, "pca_meta.rds"))

png(file.path(PLOT_DIR, "pca_scree.png"), width = 900, height = 600, res = 120)
barplot(
  pca_res$sdev^2,
  names.arg = seq_along(pca_res$sdev),
  main = "PCA scree (variance per component)",
  xlab = "Component",
  ylab = "Eigenvalue (variance)"
)
dev.off()

png(file.path(PLOT_DIR, "pca_cumulative_variance.png"), width = 900, height = 600, res = 120)
plot(
  cumprop * 100,
  type = "b",
  xlab = "Number of components",
  ylab = "Cumulative variance explained (%)",
  main = "PCA cumulative variance",
  pch = 19
)
abline(h = 95, col = "red", lty = 2)
abline(h = 90, col = "blue", lty = 2)
legend("bottomright", legend = c("90%", "95%"), col = c("blue", "red"), lty = 2)
dev.off()

pc1 <- pca_res$x[, 1]
pc2 <- pca_res$x[, 2]
cols <- ifelse(train_final$target == 0L, grDevices::rgb(0, 0, 1, 0.25), grDevices::rgb(1, 0, 0, 0.25))
png(file.path(PLOT_DIR, "pca_pc1_pc2_target.png"), width = 900, height = 600, res = 120)
plot(
  pc1,
  pc2,
  col = cols,
  pch = 16,
  cex = 0.35,
  main = "PCA: PC1 vs PC2 (training)",
  xlab = "PC1",
  ylab = "PC2"
)
legend("topright", legend = c("Normal", "Malicious"), col = c("blue", "red"), pch = 16, bty = "n")
dev.off()

Z_train <- as.data.frame(predict(pca_res, X_train))
Z_test <- as.data.frame(predict(pca_res, X_test))
Z_train$target <- train_final$target
Z_test$target <- test_final$target

saveRDS(Z_train, file.path(DATA_DIR, "train_pc_scores.rds"))
saveRDS(Z_test, file.path(DATA_DIR, "test_pc_scores.rds"))

message(
  "PCA complete. PCs for 90% / 95% variance: ",
  npc90, " / ", npc95,
  ". Scores saved to train_pc_scores.rds / test_pc_scores.rds."
)
