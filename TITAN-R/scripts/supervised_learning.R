if (!exists("DATA_DIR")) {
  if (exists("SCRIPT_DIR")) {
    source(file.path(SCRIPT_DIR, "paths.R"))
  } else {
    source(file.path(getwd(), "paths.R"))
  }
}

suppressPackageStartupMessages({
  library(e1071)
  library(class)
})
message("Supervised step: quick laptop defaults (small tuning sets, 3-fold CV, small SVM grid).")

bin_metrics <- function(pred, actual) {
  pred <- as.integer(pred)
  actual <- as.integer(actual)
  TP <- sum(pred == 1L & actual == 1L, na.rm = TRUE)
  TN <- sum(pred == 0L & actual == 0L, na.rm = TRUE)
  FP <- sum(pred == 1L & actual == 0L, na.rm = TRUE)
  FN <- sum(pred == 0L & actual == 1L, na.rm = TRUE)
  acc <- (TP + TN) / max(length(actual), 1L)
  sens <- if ((TP + FN) > 0) TP / (TP + FN) else NA_real_
  spec <- if ((TN + FP) > 0) TN / (TN + FP) else NA_real_
  c(accuracy = acc, sensitivity = sens, specificity = spec, test_error_rate = 1 - acc)
}

stratified_sample_indices <- function(y, idx, cap) {
  idx <- as.integer(idx)
  if (length(idx) <= cap) {
    return(idx)
  }
  ys <- y[idx]
  p1 <- sum(ys == 1L) / length(ys)
  n1 <- max(1L, min(sum(ys == 1L), round(cap * p1)))
  n0 <- max(1L, min(sum(ys == 0L), cap - n1))
  n1 <- min(n1, sum(ys == 1L))
  n0 <- min(n0, sum(ys == 0L))
  i0 <- sample(idx[ys == 0L], n0)
  i1 <- sample(idx[ys == 1L], n1)
  c(i0, i1)
}

knn_cv_best_k <- function(X, y, tune_rows, k_max = 21L, nfold = NULL) {
  Xt <- X[tune_rows, , drop = FALSE]
  yt <- y[tune_rows]
  n <- nrow(Xt)
  if (is.null(nfold)) {
    nfold <- 3L
  }
  message("    KNN CV: n=", n, " p=", ncol(Xt), " folds=", nfold, " k=1..", k_max)
  folds <- sample(rep(seq_len(nfold), length.out = n))
  acc_k <- numeric(k_max)
  for (k in seq_len(k_max)) {
    fa <- numeric(nfold)
    for (f in seq_len(nfold)) {
      tr <- folds != f
      te <- folds == f
      if (sum(tr) < k || sum(te) < 1L) {
        fa[f] <- NA_real_
        next
      }
      pred <- knn(
        Xt[tr, , drop = FALSE],
        Xt[te, , drop = FALSE],
        cl = factor(yt[tr], levels = c(0L, 1L)),
        k = k
      )
      pred <- as.integer(as.character(pred))
      fa[f] <- mean(pred == yt[te])
    }
    acc_k[k] <- mean(fa, na.rm = TRUE)
    if (k %% 5L == 0L || k == k_max) {
      message("    KNN CV: finished k=", k, " / ", k_max)
      flush.console()
    }
  }
  list(k = which.max(acc_k), acc_k = acc_k, nfold = nfold)
}

train_final <- readRDS(file.path(DATA_DIR, "train_final.rds"))
test_final <- readRDS(file.path(DATA_DIR, "test_final.rds"))
Z_train <- readRDS(file.path(DATA_DIR, "train_pc_scores.rds"))
Z_test <- readRDS(file.path(DATA_DIR, "test_pc_scores.rds"))
pca_meta <- readRDS(file.path(DATA_DIR, "pca_meta.rds"))
npc <- pca_meta$npc95

feat <- setdiff(names(train_final), c("target", "attack_category"))
X_all <- as.matrix(train_final[, feat, drop = FALSE])
y_all <- train_final$target
X_kddtest <- as.matrix(test_final[, feat, drop = FALSE])
y_kddtest <- test_final$target

pc_cols <- paste0("PC", seq_len(npc))
Z_all_train <- as.matrix(Z_train[, pc_cols, drop = FALSE])
Z_kddtest <- as.matrix(Z_test[, pc_cols, drop = FALSE])

set.seed(4323)
n <- nrow(X_all)
hold_n <- floor(0.2 * n)
te_idx <- sample.int(n, hold_n)
tr_idx <- setdiff(seq_len(n), te_idx)

X_tr <- X_all[tr_idx, , drop = FALSE]
X_te <- X_all[te_idx, , drop = FALSE]
y_tr <- y_all[tr_idx]
y_te <- y_all[te_idx]

Z_tr <- Z_all_train[tr_idx, , drop = FALSE]
Z_te <- Z_all_train[te_idx, , drop = FALSE]

max_tune_rows <- function() {
  suppressWarnings(as.integer(Sys.getenv("TITAN_TUNE_ROWS", unset = "2000")))
}
max_svm_tune_rows <- function() {
  suppressWarnings(as.integer(Sys.getenv("TITAN_SVM_TUNE_ROWS", unset = "1000")))
}

cap <- max_tune_rows()
tune_idx <- if (length(y_tr) > cap) {
  stratified_sample_indices(y_tr, seq_along(y_tr), cap)
} else {
  seq_along(y_tr)
}
message("Quick run: KNN tuning on ", length(tune_idx), " rows.")

svm_tune_idx <- stratified_sample_indices(y_tr, tune_idx, min(length(tune_idx), max_svm_tune_rows()))
message("Quick run: SVM tuning on ", length(svm_tune_idx), " rows (3-fold CV).")

fit_knn_cv <- function(X, y, label) {
  message("KNN CV (k=1:21) on tuning subset [", label, "] ...")
  knn_cv_best_k(X, y, tune_idx, k_max = 21L, nfold = NULL)
}

fit_svm_tune <- function(X, y, label) {
  n_svm <- length(svm_tune_idx)
  svm_fold <- 3L
  message("SVM RBF tune.svm (", svm_fold, "-fold) on ", n_svm, " rows [", label, "] ...")
  # tune.svm builds "ranges" from cost/gamma formals; do not pass ranges= (it duplicates via ...).
  tobj <- tune.svm(
    x = X[svm_tune_idx, , drop = FALSE],
    y = factor(y[svm_tune_idx], levels = c(0L, 1L)),
    kernel = "radial",
    cost = c(1, 10),
    gamma = c(1e-2, 0.1),
    tunecontrol = tune.control(sampling = "cross", cross = svm_fold)
  )
  best <- tobj$best.parameters
  list(tune = tobj, cost = best$cost, gamma = best$gamma)
}

predict_knn <- function(Xtr, Xev, ytr, k) {
  as.integer(as.character(knn(train = Xtr, test = Xev, cl = factor(ytr, levels = c(0L, 1L)), k = k)))
}

knn_reference_cap <- function() {
  suppressWarnings(as.integer(Sys.getenv("TITAN_KNN_TRAIN_CAP", unset = "4000")))
}

predict_knn_capped <- function(Xtr, Xev, ytr, k, label = "") {
  cap <- knn_reference_cap()
  if (is.infinite(cap) || nrow(Xtr) <= cap) {
    return(predict_knn(Xtr, Xev, ytr, k))
  }
  j <- stratified_sample_indices(ytr, seq_len(nrow(Xtr)), cap)
  message("    KNN predict: ", length(j), " ref rows ", label)
  predict_knn(Xtr[j, , drop = FALSE], Xev, ytr[j], k)
}

predict_svm_df <- function(mod, Xev) {
  as.integer(as.character(predict(mod, as.data.frame(Xev))))
}

svm_train_cap <- function() {
  v <- Sys.getenv("TITAN_SVM_CAP", unset = "3500")
  if (toupper(v) == "INF") {
    return(Inf)
  }
  suppressWarnings(as.integer(v))
}

stratified_subsample <- function(X, y, cap) {
  if (is.infinite(cap) || nrow(X) <= cap) {
    return(list(X = X, y = y))
  }
  y <- as.integer(y)
  n0 <- sum(y == 0L)
  n1 <- sum(y == 1L)
  t0 <- floor(cap * n0 / length(y))
  t1 <- cap - t0
  i0 <- sample(which(y == 0L), min(t0, n0))
  i1 <- sample(which(y == 1L), min(t1, n1))
  j <- c(i0, i1)
  list(X = X[j, , drop = FALSE], y = y[j])
}

run_block <- function(X_tr, X_te, X_kdd, y_tr, y_te, y_kdd, tag) {
  message("[", tag, "] start run_block")
  kn <- fit_knn_cv(X_tr, y_tr, tag)
  sv <- fit_svm_tune(X_tr, y_tr, tag)
  message("[", tag, "] tuning done; scoring holdout and KDDTest+ ...")

  pred_k_te <- predict_knn_capped(X_tr, X_te, y_tr, kn$k, paste0("[", tag, " holdout]"))
  cap <- svm_train_cap()
  sub_xy <- stratified_subsample(X_tr, y_tr, cap)
  if (nrow(sub_xy$X) < nrow(X_tr)) {
    message("SVM refit on ", nrow(sub_xy$X), " rows [", tag, "] (quick cap).")
  }
  df_tr <- data.frame(sub_xy$X, y = factor(sub_xy$y, levels = c(0L, 1L)))
  svm_full <- svm(y ~ ., data = df_tr, kernel = "radial", cost = sv$cost, gamma = sv$gamma)
  pred_s_te <- predict_svm_df(svm_full, X_te)

  pred_k_kdd <- predict_knn_capped(X_tr, X_kdd, y_tr, kn$k, paste0("[", tag, " KDDTest+]"))
  pred_s_kdd <- predict_svm_df(svm_full, X_kdd)

  row_df <- function(model, dataset, pred, actual) {
    pred <- as.integer(pred)
    actual <- as.integer(actual)
    bm <- bin_metrics(pred, actual)
    data.frame(
      space = tag,
      model = model,
      dataset = dataset,
      accuracy = bm[["accuracy"]],
      sensitivity = bm[["sensitivity"]],
      specificity = bm[["specificity"]],
      test_error_rate = bm[["test_error_rate"]],
      stringsAsFactors = FALSE
    )
  }

  met <- rbind(
    row_df("KNN", "train_holdout_20pct", pred_k_te, y_te),
    row_df("KNN", "KDDTest+", pred_k_kdd, y_kdd),
    row_df("SVM_RBF", "train_holdout_20pct", pred_s_te, y_te),
    row_df("SVM_RBF", "KDDTest+", pred_s_kdd, y_kdd)
  )

  list(
    metrics = met,
    knn_k = kn$k,
    svm_cost = sv$cost,
    svm_gamma = sv$gamma,
    svm_mod = svm_full,
    pred_k_te = pred_k_te,
    pred_s_te = pred_s_te
  )
}

res_raw <- run_block(X_tr, X_te, X_kddtest, y_tr, y_te, y_kddtest, "raw_scaled")
res_pc <- run_block(Z_tr, Z_te, Z_kddtest, y_tr, y_te, y_kddtest, paste0("PC1_PC", npc))

metrics_tbl <- rbind(res_raw$metrics, res_pc$metrics)
write.csv(metrics_tbl, file.path(DATA_DIR, "supervised_metrics.csv"), row.names = FALSE)
message("Supervised metrics written to ", file.path(DATA_DIR, "supervised_metrics.csv"))

hold <- metrics_tbl[metrics_tbl$dataset == "train_holdout_20pct", ]
best_row <- hold[which.max(hold$accuracy), ]
message("Best on 20% holdout: ", best_row$space, " ", best_row$model, " acc=", round(best_row$accuracy, 4))

champion_space <- as.character(best_row$space)
champion_model <- as.character(best_row$model)

if (champion_model == "KNN") {
  if (champion_space == "raw_scaled") {
    best_k <- res_raw$knn_k
    pred_champ_test <- predict_knn_capped(X_all, X_kddtest, y_all, best_k, "[champion raw]")
    champ_desc <- paste0("KNN_raw_k", best_k)
  } else {
    best_k <- res_pc$knn_k
    pred_champ_test <- predict_knn_capped(Z_all_train, Z_kddtest, y_all, best_k, "[champion PC]")
    champ_desc <- paste0("KNN_PC_k", best_k)
  }
} else {
  if (champion_space == "raw_scaled") {
    cap <- svm_train_cap()
    subf <- stratified_subsample(X_all, y_all, cap)
    df_full <- data.frame(subf$X, y = factor(subf$y, levels = c(0L, 1L)))
    champ <- svm(y ~ ., data = df_full, kernel = "radial", cost = res_raw$svm_cost, gamma = res_raw$svm_gamma)
    pred_champ_test <- predict_svm_df(champ, X_kddtest)
    champ_desc <- paste0("SVM_raw_cost", res_raw$svm_cost, "_g", res_raw$svm_gamma)
  } else {
    cap <- svm_train_cap()
    subf <- stratified_subsample(Z_all_train, y_all, cap)
    df_full <- data.frame(subf$X, y = factor(subf$y, levels = c(0L, 1L)))
    champ <- svm(y ~ ., data = df_full, kernel = "radial", cost = res_pc$svm_cost, gamma = res_pc$svm_gamma)
    pred_champ_test <- predict_svm_df(champ, Z_kddtest)
    champ_desc <- paste0("SVM_PC_cost", res_pc$svm_cost, "_g", res_pc$svm_gamma)
  }
}

champ_summary <- data.frame(
  champion = champ_desc,
  t(bin_metrics(pred_champ_test, y_kddtest))
)
write.csv(champ_summary, file.path(DATA_DIR, "champion_kddtest_metrics.csv"), row.names = FALSE)
message("Champion refit on 100% training; KDDTest+ metrics saved.")

saveRDS(
  list(
    champion_desc = champ_desc,
    champion_space = champion_space,
    champion_model = champion_model,
    raw = res_raw,
    pc = res_pc
  ),
  file.path(DATA_DIR, "supervised_models.rds")
)

# --- SVM decision boundary in PC1–PC2 (base graphics, quick) ---
set.seed(4323)
sub_n <- min(1200L, nrow(Z_train))
sub_i <- sample.int(nrow(Z_train), sub_n)
df2 <- data.frame(PC1 = Z_train$PC1[sub_i], PC2 = Z_train$PC2[sub_i], y = factor(y_all[sub_i], levels = c(0L, 1L)))
message("2D SVM boundary (quick): tuning on ", nrow(df2), " points ...")
t2 <- tune.svm(
  y ~ PC1 + PC2,
  data = df2,
  kernel = "radial",
  cost = c(0.1, 1),
  gamma = c(0.1, 0.5),
  tunecontrol = tune.control(sampling = "cross", cross = 2)
)
svm2d <- t2$best.model
rng1 <- range(Z_train$PC1)
rng2 <- range(Z_train$PC2)
ng <- 32L
g1 <- seq(rng1[1], rng1[2], length.out = ng)
g2 <- seq(rng2[1], rng2[2], length.out = ng)
grid_df <- expand.grid(PC1 = g1, PC2 = g2)
pr <- as.integer(as.character(predict(svm2d, grid_df)))
zm <- matrix(pr, nrow = ng, ncol = ng, byrow = TRUE)
png(file.path(PLOT_DIR, "svm_decision_boundary_pc1_pc2.png"), width = 1000, height = 750, res = 120)
filled.contour(
  g1,
  g2,
  zm,
  color.palette = function(n) grDevices::hcl.colors(n, "BluYl", rev = TRUE),
  main = "SVM (RBF) decision regions in PC1–PC2 (subset tune)",
  xlab = "PC1",
  ylab = "PC2"
)
points(Z_train$PC1[sub_i], Z_train$PC2[sub_i], col = ifelse(y_all[sub_i] == 0L, grDevices::rgb(0, 0, 1, 0.35), grDevices::rgb(1, 0, 0, 0.35)), pch = 16, cex = 0.35)
legend("topright", legend = c("True 0", "True 1"), col = c("blue", "red"), pch = 16, bty = "n")
dev.off()

message("Supervised learning complete.")
