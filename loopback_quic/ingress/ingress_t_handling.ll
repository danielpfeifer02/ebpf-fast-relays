; ModuleID = 'ingress/ingress_t_handling.c'
source_filename = "ingress/ingress_t_handling.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.anon = type { [2 x i32]*, i32*, %struct.meta_struc*, [1 x i32]* }
%struct.meta_struc = type { i32 }
%struct.xdp_md = type { i32, i32, i32, i32, i32, i32 }

@meta = dso_local global %struct.anon zeroinitializer, section ".maps", align 8, !dbg !0
@handle_ingress.____fmt = internal constant [26 x i8] c"meta table value is null\0A\00", align 1, !dbg !76
@handle_ingress.____fmt.1 = internal constant [41 x i8] c"[ingress xdp] meta table value is %p %d\0A\00", align 1, !dbg !184
@handle_ingress.____fmt.2 = internal constant [26 x i8] c"[ingress xdp] cidLen: %d\0A\00", align 1, !dbg !189
@handle_ingress.____fmt.3 = internal constant [53 x i8] c"[ingress xdp] packet is entering (payload size: %d)\0A\00", align 1, !dbg !191
@handle_ingress.____fmt.4 = internal constant [27 x i8] c"[ingress xdp] LONG HEADER\0A\00", align 1, !dbg !202
@handle_ingress.____fmt.5 = internal constant [28 x i8] c"[ingress xdp] SHORT HEADER\0A\00", align 1, !dbg !215
@handle_ingress.____fmt.6 = internal constant [46 x i8] c"[ingress xdp] connection id length not found\0A\00", align 1, !dbg !220
@handle_ingress.____fmt.7 = internal constant [40 x i8] c"[ingress xdp] packet number length: %d\0A\00", align 1, !dbg !225
@handle_ingress.____fmt.8 = internal constant [85 x i8] c"[ingress xdp] packet number (%d bytes long): %d (based on connection id length: %d)\0A\00", align 1, !dbg !230
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !235
@llvm.compiler.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (i32 (%struct.xdp_md*)* @handle_ingress to i8*), i8* bitcast (%struct.anon* @meta to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @handle_ingress(%struct.xdp_md* nocapture noundef readonly %0) #0 section "xdp" !dbg !78 {
  %2 = alloca i32, align 4
  %3 = alloca [256 x i8], align 1
  %4 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !94, metadata !DIExpression()), !dbg !260
  %5 = bitcast i32* %2 to i8*, !dbg !261
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %5) #5, !dbg !261
  call void @llvm.dbg.value(metadata i32 0, metadata !95, metadata !DIExpression()), !dbg !260
  store i32 0, i32* %2, align 4, !dbg !262, !tbaa !263
  call void @llvm.dbg.value(metadata i32* %2, metadata !95, metadata !DIExpression(DW_OP_deref)), !dbg !260
  %6 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon* @meta to i8*), i8* noundef nonnull %5) #5, !dbg !267
  call void @llvm.dbg.value(metadata i8* %6, metadata !96, metadata !DIExpression()), !dbg !260
  %7 = icmp eq i8* %6, null, !dbg !268
  br i1 %7, label %8, label %10, !dbg !270

8:                                                ; preds = %1
  %9 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([26 x i8], [26 x i8]* @handle_ingress.____fmt, i64 0, i64 0), i32 noundef 26) #5, !dbg !271
  br label %121, !dbg !274

10:                                               ; preds = %1
  call void @llvm.dbg.value(metadata i8* %6, metadata !96, metadata !DIExpression()), !dbg !260
  %11 = bitcast i8* %6 to i32*, !dbg !275
  %12 = load i32, i32* %11, align 4, !dbg !275, !tbaa !278
  %13 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([41 x i8], [41 x i8]* @handle_ingress.____fmt.1, i64 0, i64 0), i32 noundef 41, i8* noundef nonnull %6, i32 noundef %12) #5, !dbg !275
  %14 = load i32, i32* %11, align 4, !dbg !280, !tbaa !278
  call void @llvm.dbg.value(metadata i32 %14, metadata !101, metadata !DIExpression()), !dbg !260
  %15 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([26 x i8], [26 x i8]* @handle_ingress.____fmt.2, i64 0, i64 0), i32 noundef 26, i32 noundef %14) #5, !dbg !281
  %16 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !283
  %17 = load i32, i32* %16, align 4, !dbg !283, !tbaa !284
  %18 = zext i32 %17 to i64, !dbg !286
  %19 = inttoptr i64 %18 to i8*, !dbg !287
  call void @llvm.dbg.value(metadata i8* %19, metadata !102, metadata !DIExpression()), !dbg !260
  %20 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !288
  %21 = load i32, i32* %20, align 4, !dbg !288, !tbaa !289
  %22 = zext i32 %21 to i64, !dbg !290
  %23 = inttoptr i64 %22 to i8*, !dbg !291
  call void @llvm.dbg.value(metadata i8* %23, metadata !103, metadata !DIExpression()), !dbg !260
  call void @llvm.dbg.value(metadata i8* %23, metadata !105, metadata !DIExpression()), !dbg !260
  %24 = getelementptr i8, i8* %23, i64 14, !dbg !292
  %25 = icmp ugt i8* %24, %19, !dbg !294
  br i1 %25, label %121, label %26, !dbg !295

26:                                               ; preds = %10
  call void @llvm.dbg.value(metadata i8* %24, metadata !130, metadata !DIExpression()), !dbg !260
  %27 = getelementptr i8, i8* %23, i64 34, !dbg !296
  %28 = icmp ugt i8* %27, %19, !dbg !298
  br i1 %28, label %121, label %29, !dbg !299

29:                                               ; preds = %26
  call void @llvm.dbg.value(metadata i8* %24, metadata !130, metadata !DIExpression()), !dbg !260
  %30 = getelementptr i8, i8* %23, i64 23, !dbg !300
  %31 = load i8, i8* %30, align 1, !dbg !300, !tbaa !302
  %32 = icmp eq i8 %31, 17, !dbg !305
  br i1 %32, label %33, label %121, !dbg !306

33:                                               ; preds = %29
  call void @llvm.dbg.value(metadata i8* %27, metadata !120, metadata !DIExpression()), !dbg !260
  %34 = getelementptr i8, i8* %23, i64 42, !dbg !307
  %35 = icmp ugt i8* %34, %19, !dbg !309
  br i1 %35, label %121, label %36, !dbg !310

36:                                               ; preds = %33
  %37 = getelementptr i8, i8* %23, i64 36, !dbg !311
  %38 = bitcast i8* %37 to i16*, !dbg !311
  %39 = load i16, i16* %38, align 2, !dbg !311, !tbaa !313
  %40 = icmp eq i16 %39, -28144, !dbg !315
  br i1 %40, label %45, label %41, !dbg !316

41:                                               ; preds = %36
  %42 = bitcast i8* %27 to i16*, !dbg !317
  %43 = load i16, i16* %42, align 2, !dbg !317, !tbaa !318
  %44 = icmp eq i16 %43, -28144, !dbg !319
  br i1 %44, label %45, label %121, !dbg !320

45:                                               ; preds = %41, %36
  call void @llvm.dbg.value(metadata i8* %34, metadata !119, metadata !DIExpression()), !dbg !260
  %46 = getelementptr i8, i8* %23, i64 38, !dbg !321
  %47 = bitcast i8* %46 to i16*, !dbg !321
  %48 = load i16, i16* %47, align 2, !dbg !321, !tbaa !322
  %49 = call i16 @llvm.bswap.i16(i16 %48) #5
  %50 = zext i16 %49 to i32, !dbg !321
  %51 = add nsw i32 %50, -8, !dbg !323
  call void @llvm.dbg.value(metadata i32 %51, metadata !104, metadata !DIExpression()), !dbg !260
  %52 = zext i32 %51 to i64, !dbg !324
  %53 = getelementptr i8, i8* %34, i64 %52, !dbg !324
  %54 = icmp ugt i8* %53, %19, !dbg !326
  br i1 %54, label %121, label %55, !dbg !327

55:                                               ; preds = %45
  %56 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([53 x i8], [53 x i8]* @handle_ingress.____fmt.3, i64 0, i64 0), i32 noundef 53, i32 noundef %51) #5, !dbg !328
  %57 = getelementptr inbounds [256 x i8], [256 x i8]* %3, i64 0, i64 0, !dbg !330
  call void @llvm.lifetime.start.p0i8(i64 256, i8* nonnull %57) #5, !dbg !330
  call void @llvm.dbg.declare(metadata [256 x i8]* %3, metadata !159, metadata !DIExpression()), !dbg !331
  call void @llvm.memset.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(256) %57, i8 0, i64 256, i1 false), !dbg !331
  %58 = call i64 inttoptr (i64 113 to i64 (i8*, i32, i8*)*)(i8* noundef nonnull %57, i32 noundef 256, i8* noundef %34) #5, !dbg !332
  call void @llvm.dbg.value(metadata [256 x i8]* %3, metadata !163, metadata !DIExpression()), !dbg !260
  %59 = load i8, i8* %57, align 1, !dbg !333, !tbaa !334
  %60 = icmp sgt i8 %59, -1, !dbg !336
  br i1 %60, label %68, label %61, !dbg !337

61:                                               ; preds = %55
  %62 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([27 x i8], [27 x i8]* @handle_ingress.____fmt.4, i64 0, i64 0), i32 noundef 27) #5, !dbg !338
  %63 = bitcast i32* %4 to i8*, !dbg !340
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %63) #5, !dbg !340
  %64 = getelementptr inbounds [256 x i8], [256 x i8]* %3, i64 0, i64 6, !dbg !341
  %65 = load i8, i8* %64, align 1, !dbg !341, !tbaa !342
  %66 = zext i8 %65 to i32, !dbg !341
  call void @llvm.dbg.value(metadata i32 %66, metadata !164, metadata !DIExpression()), !dbg !343
  store i32 %66, i32* %4, align 4, !dbg !344, !tbaa !263
  call void @llvm.dbg.value(metadata i32* %2, metadata !95, metadata !DIExpression(DW_OP_deref)), !dbg !260
  call void @llvm.dbg.value(metadata i32* %4, metadata !164, metadata !DIExpression(DW_OP_deref)), !dbg !343
  %67 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i8* noundef bitcast (%struct.anon* @meta to i8*), i8* noundef nonnull %5, i8* noundef nonnull %63, i64 noundef 0) #5, !dbg !345
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %63) #5, !dbg !346
  br label %120, !dbg !347

68:                                               ; preds = %55
  %69 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([28 x i8], [28 x i8]* @handle_ingress.____fmt.5, i64 0, i64 0), i32 noundef 28) #5, !dbg !348
  call void @llvm.dbg.value(metadata i32 1, metadata !167, metadata !DIExpression()), !dbg !350
  %70 = icmp eq i32 %14, 0, !dbg !351
  br i1 %70, label %71, label %73, !dbg !353

71:                                               ; preds = %68
  %72 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([46 x i8], [46 x i8]* @handle_ingress.____fmt.6, i64 0, i64 0), i32 noundef 46) #5, !dbg !354
  br label %120, !dbg !357

73:                                               ; preds = %68
  %74 = load i8, i8* %57, align 1, !dbg !358, !tbaa !334
  %75 = and i8 %74, 3, !dbg !359
  %76 = zext i8 %75 to i32, !dbg !359
  call void @llvm.dbg.value(metadata i32 %76, metadata !169, metadata !DIExpression()), !dbg !350
  %77 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([40 x i8], [40 x i8]* @handle_ingress.____fmt.7, i64 0, i64 0), i32 noundef 40, i32 noundef %76) #5, !dbg !360
  call void @llvm.dbg.value(metadata i32 0, metadata !170, metadata !DIExpression()), !dbg !350
  %78 = trunc i32 %14 to i8, !dbg !362
  %79 = add i8 %78, 1, !dbg !362
  call void @llvm.dbg.value(metadata i8 %79, metadata !171, metadata !DIExpression()), !dbg !350
  %80 = trunc i8 %74 to i2, !dbg !363
  switch i2 %80, label %117 [
    i2 1, label %81
    i2 -2, label %86
    i2 -1, label %97
  ], !dbg !363

81:                                               ; preds = %73
  %82 = zext i8 %79 to i64, !dbg !364
  %83 = getelementptr inbounds [256 x i8], [256 x i8]* %3, i64 0, i64 %82, !dbg !364
  %84 = load i8, i8* %83, align 1, !dbg !364, !tbaa !342
  %85 = zext i8 %84 to i32, !dbg !364
  call void @llvm.dbg.value(metadata i32 %85, metadata !170, metadata !DIExpression()), !dbg !350
  br label %117, !dbg !367

86:                                               ; preds = %73
  %87 = zext i8 %79 to i64, !dbg !368
  %88 = getelementptr inbounds [256 x i8], [256 x i8]* %3, i64 0, i64 %87, !dbg !368
  %89 = load i8, i8* %88, align 1, !dbg !368, !tbaa !342
  %90 = zext i8 %89 to i32, !dbg !368
  %91 = shl nuw nsw i32 %90, 8, !dbg !371
  %92 = add nuw nsw i64 %87, 1, !dbg !372
  %93 = getelementptr inbounds [256 x i8], [256 x i8]* %3, i64 0, i64 %92, !dbg !373
  %94 = load i8, i8* %93, align 1, !dbg !373, !tbaa !342
  %95 = zext i8 %94 to i32, !dbg !373
  %96 = or i32 %91, %95, !dbg !374
  call void @llvm.dbg.value(metadata i32 %96, metadata !170, metadata !DIExpression()), !dbg !350
  br label %117, !dbg !375

97:                                               ; preds = %73
  %98 = zext i8 %79 to i64, !dbg !376
  %99 = getelementptr inbounds [256 x i8], [256 x i8]* %3, i64 0, i64 %98, !dbg !376
  %100 = load i8, i8* %99, align 1, !dbg !376, !tbaa !342
  %101 = zext i8 %100 to i32, !dbg !376
  %102 = shl nuw nsw i32 %101, 16, !dbg !379
  %103 = zext i8 %79 to i32, !dbg !380
  %104 = add nuw nsw i32 %103, 1, !dbg !381
  %105 = zext i32 %104 to i64
  %106 = getelementptr inbounds [256 x i8], [256 x i8]* %3, i64 0, i64 %105, !dbg !382
  %107 = load i8, i8* %106, align 1, !dbg !382, !tbaa !342
  %108 = zext i8 %107 to i32, !dbg !382
  %109 = shl nuw nsw i32 %108, 8, !dbg !383
  %110 = or i32 %109, %102, !dbg !384
  %111 = add nuw nsw i32 %103, 2, !dbg !385
  %112 = zext i32 %111 to i64
  %113 = getelementptr inbounds [256 x i8], [256 x i8]* %3, i64 0, i64 %112, !dbg !386
  %114 = load i8, i8* %113, align 1, !dbg !386, !tbaa !342
  %115 = zext i8 %114 to i32, !dbg !386
  %116 = or i32 %110, %115, !dbg !387
  call void @llvm.dbg.value(metadata i32 %116, metadata !170, metadata !DIExpression()), !dbg !350
  br label %117, !dbg !388

117:                                              ; preds = %73, %86, %97, %81
  %118 = phi i32 [ %85, %81 ], [ %96, %86 ], [ %116, %97 ], [ 0, %73 ], !dbg !350
  call void @llvm.dbg.value(metadata i32 %118, metadata !170, metadata !DIExpression()), !dbg !350
  %119 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([85 x i8], [85 x i8]* @handle_ingress.____fmt.8, i64 0, i64 0), i32 noundef 85, i32 noundef %76, i32 noundef %118, i32 noundef %14) #5, !dbg !389
  br label %120, !dbg !391

120:                                              ; preds = %71, %117, %61
  call void @llvm.lifetime.end.p0i8(i64 256, i8* nonnull %57) #5, !dbg !392
  br label %121

121:                                              ; preds = %120, %10, %26, %29, %33, %41, %45, %8
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %5) #5, !dbg !392
  ret i32 2, !dbg !392
}

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: argmemonly mustprogress nofree nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #3

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #4

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare i16 @llvm.bswap.i16(i16) #4

attributes #0 = { nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { mustprogress nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { argmemonly mustprogress nofree nosync nounwind willreturn }
attributes #3 = { argmemonly mustprogress nofree nounwind willreturn writeonly }
attributes #4 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #5 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!255, !256, !257, !258}
!llvm.ident = !{!259}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "meta", scope: !2, file: !3, line: 28, type: !240, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !51, globals: !66, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "ingress/ingress_t_handling.c", directory: "/home/danpfei02/Desktop/thesis/Adaptive_MoQ/loopback_quic", checksumkind: CSK_MD5, checksum: "a926f4d822fcede3e376b84bf4d9e99b")
!4 = !{!5, !14, !45}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 5433, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "", checksumkind: CSK_MD5, checksum: "03bc76f18af37c3e4503ca6e7a7f78a9")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2)
!12 = !DIEnumerator(name: "XDP_TX", value: 3)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4)
!14 = !DICompositeType(tag: DW_TAG_enumeration_type, file: !15, line: 40, baseType: !7, size: 32, elements: !16)
!15 = !DIFile(filename: "/usr/include/netinet/in.h", directory: "", checksumkind: CSK_MD5, checksum: "eb6560f10d4cfe9f30fea2c92b9da0fd")
!16 = !{!17, !18, !19, !20, !21, !22, !23, !24, !25, !26, !27, !28, !29, !30, !31, !32, !33, !34, !35, !36, !37, !38, !39, !40, !41, !42, !43, !44}
!17 = !DIEnumerator(name: "IPPROTO_IP", value: 0)
!18 = !DIEnumerator(name: "IPPROTO_ICMP", value: 1)
!19 = !DIEnumerator(name: "IPPROTO_IGMP", value: 2)
!20 = !DIEnumerator(name: "IPPROTO_IPIP", value: 4)
!21 = !DIEnumerator(name: "IPPROTO_TCP", value: 6)
!22 = !DIEnumerator(name: "IPPROTO_EGP", value: 8)
!23 = !DIEnumerator(name: "IPPROTO_PUP", value: 12)
!24 = !DIEnumerator(name: "IPPROTO_UDP", value: 17)
!25 = !DIEnumerator(name: "IPPROTO_IDP", value: 22)
!26 = !DIEnumerator(name: "IPPROTO_TP", value: 29)
!27 = !DIEnumerator(name: "IPPROTO_DCCP", value: 33)
!28 = !DIEnumerator(name: "IPPROTO_IPV6", value: 41)
!29 = !DIEnumerator(name: "IPPROTO_RSVP", value: 46)
!30 = !DIEnumerator(name: "IPPROTO_GRE", value: 47)
!31 = !DIEnumerator(name: "IPPROTO_ESP", value: 50)
!32 = !DIEnumerator(name: "IPPROTO_AH", value: 51)
!33 = !DIEnumerator(name: "IPPROTO_MTP", value: 92)
!34 = !DIEnumerator(name: "IPPROTO_BEETPH", value: 94)
!35 = !DIEnumerator(name: "IPPROTO_ENCAP", value: 98)
!36 = !DIEnumerator(name: "IPPROTO_PIM", value: 103)
!37 = !DIEnumerator(name: "IPPROTO_COMP", value: 108)
!38 = !DIEnumerator(name: "IPPROTO_SCTP", value: 132)
!39 = !DIEnumerator(name: "IPPROTO_UDPLITE", value: 136)
!40 = !DIEnumerator(name: "IPPROTO_MPLS", value: 137)
!41 = !DIEnumerator(name: "IPPROTO_ETHERNET", value: 143)
!42 = !DIEnumerator(name: "IPPROTO_RAW", value: 255)
!43 = !DIEnumerator(name: "IPPROTO_MPTCP", value: 262)
!44 = !DIEnumerator(name: "IPPROTO_MAX", value: 263)
!45 = !DICompositeType(tag: DW_TAG_enumeration_type, file: !6, line: 1168, baseType: !7, size: 32, elements: !46)
!46 = !{!47, !48, !49, !50}
!47 = !DIEnumerator(name: "BPF_ANY", value: 0)
!48 = !DIEnumerator(name: "BPF_NOEXIST", value: 1)
!49 = !DIEnumerator(name: "BPF_EXIST", value: 2)
!50 = !DIEnumerator(name: "BPF_F_LOCK", value: 4)
!51 = !{!52, !53, !54, !56, !64}
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!53 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !55, size: 64)
!55 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!56 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !57, size: 64)
!57 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "quic_header_wrapper", file: !3, line: 14, size: 8, elements: !58)
!58 = !{!59}
!59 = !DIDerivedType(tag: DW_TAG_member, name: "header_t", scope: !57, file: !3, line: 15, baseType: !60, size: 8)
!60 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint8_t", file: !61, line: 24, baseType: !62)
!61 = !DIFile(filename: "/usr/include/bits/stdint-uintn.h", directory: "", checksumkind: CSK_MD5, checksum: "2bf2ae53c58c01b1a1b9383b5195125c")
!62 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint8_t", file: !63, line: 38, baseType: !55)
!63 = !DIFile(filename: "/usr/include/bits/types.h", directory: "", checksumkind: CSK_MD5, checksum: "d108b5f93a74c50510d7d9bc0ab36df9")
!64 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint16_t", file: !63, line: 40, baseType: !65)
!65 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!66 = !{!67, !76, !177, !184, !189, !191, !196, !202, !207, !215, !220, !225, !230, !235, !0}
!67 = !DIGlobalVariableExpression(var: !68, expr: !DIExpression())
!68 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !69, line: 56, type: !70, isLocal: true, isDefinition: true)
!69 = !DIFile(filename: "../libbpf/src/bpf_helper_defs.h", directory: "/home/danpfei02/Desktop/thesis/Adaptive_MoQ/loopback_quic", checksumkind: CSK_MD5, checksum: "65e4dc8e3121f91a5c2c9eb8563c5692")
!70 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !71)
!71 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !72, size: 64)
!72 = !DISubroutineType(types: !73)
!73 = !{!52, !52, !74}
!74 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !75, size: 64)
!75 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!76 = !DIGlobalVariableExpression(var: !77, expr: !DIExpression())
!77 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 39, type: !172, isLocal: true, isDefinition: true)
!78 = distinct !DISubprogram(name: "handle_ingress", scope: !3, file: !3, line: 33, type: !79, scopeLine: 34, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !93)
!79 = !DISubroutineType(types: !80)
!80 = !{!81, !82}
!81 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!82 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !83, size: 64)
!83 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 5444, size: 192, elements: !84)
!84 = !{!85, !88, !89, !90, !91, !92}
!85 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !83, file: !6, line: 5445, baseType: !86, size: 32)
!86 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !87, line: 27, baseType: !7)
!87 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "", checksumkind: CSK_MD5, checksum: "b810f270733e106319b67ef512c6246e")
!88 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !83, file: !6, line: 5446, baseType: !86, size: 32, offset: 32)
!89 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !83, file: !6, line: 5447, baseType: !86, size: 32, offset: 64)
!90 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !83, file: !6, line: 5449, baseType: !86, size: 32, offset: 96)
!91 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !83, file: !6, line: 5450, baseType: !86, size: 32, offset: 128)
!92 = !DIDerivedType(tag: DW_TAG_member, name: "egress_ifindex", scope: !83, file: !6, line: 5452, baseType: !86, size: 32, offset: 160)
!93 = !{!94, !95, !96, !101, !102, !103, !104, !105, !119, !120, !130, !159, !163, !164, !167, !169, !170, !171}
!94 = !DILocalVariable(name: "ctx", arg: 1, scope: !78, file: !3, line: 33, type: !82)
!95 = !DILocalVariable(name: "index", scope: !78, file: !3, line: 36, type: !81)
!96 = !DILocalVariable(name: "meta_value", scope: !78, file: !3, line: 37, type: !97)
!97 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !98, size: 64)
!98 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "meta_struc", file: !3, line: 18, size: 32, elements: !99)
!99 = !{!100}
!100 = !DIDerivedType(tag: DW_TAG_member, name: "connIdLength", scope: !98, file: !3, line: 19, baseType: !81, size: 32)
!101 = !DILocalVariable(name: "cidLen", scope: !78, file: !3, line: 45, type: !81)
!102 = !DILocalVariable(name: "data_end", scope: !78, file: !3, line: 50, type: !52)
!103 = !DILocalVariable(name: "data", scope: !78, file: !3, line: 51, type: !52)
!104 = !DILocalVariable(name: "payload_size", scope: !78, file: !3, line: 53, type: !7)
!105 = !DILocalVariable(name: "eth", scope: !78, file: !3, line: 54, type: !106)
!106 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !107, size: 64)
!107 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !108, line: 168, size: 112, elements: !109)
!108 = !DIFile(filename: "/usr/include/linux/if_ether.h", directory: "", checksumkind: CSK_MD5, checksum: "ab0320da726e75d904811ce344979934")
!109 = !{!110, !114, !115}
!110 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !107, file: !108, line: 169, baseType: !111, size: 48)
!111 = !DICompositeType(tag: DW_TAG_array_type, baseType: !55, size: 48, elements: !112)
!112 = !{!113}
!113 = !DISubrange(count: 6)
!114 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !107, file: !108, line: 170, baseType: !111, size: 48, offset: 48)
!115 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !107, file: !108, line: 171, baseType: !116, size: 16, offset: 96)
!116 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !117, line: 25, baseType: !118)
!117 = !DIFile(filename: "/usr/include/linux/types.h", directory: "", checksumkind: CSK_MD5, checksum: "52ec79a38e49ac7d1dc9e146ba88a7b1")
!118 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !87, line: 24, baseType: !65)
!119 = !DILocalVariable(name: "payload", scope: !78, file: !3, line: 55, type: !54)
!120 = !DILocalVariable(name: "udp", scope: !78, file: !3, line: 56, type: !121)
!121 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !122, size: 64)
!122 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "udphdr", file: !123, line: 23, size: 64, elements: !124)
!123 = !DIFile(filename: "/usr/include/linux/udp.h", directory: "", checksumkind: CSK_MD5, checksum: "53c0d42e1bf6d93b39151764be2d20fb")
!124 = !{!125, !126, !127, !128}
!125 = !DIDerivedType(tag: DW_TAG_member, name: "source", scope: !122, file: !123, line: 24, baseType: !116, size: 16)
!126 = !DIDerivedType(tag: DW_TAG_member, name: "dest", scope: !122, file: !123, line: 25, baseType: !116, size: 16, offset: 16)
!127 = !DIDerivedType(tag: DW_TAG_member, name: "len", scope: !122, file: !123, line: 26, baseType: !116, size: 16, offset: 32)
!128 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !122, file: !123, line: 27, baseType: !129, size: 16, offset: 48)
!129 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sum16", file: !117, line: 31, baseType: !118)
!130 = !DILocalVariable(name: "ip", scope: !78, file: !3, line: 57, type: !131)
!131 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !132, size: 64)
!132 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "iphdr", file: !133, line: 87, size: 160, elements: !134)
!133 = !DIFile(filename: "/usr/include/linux/ip.h", directory: "", checksumkind: CSK_MD5, checksum: "042b09a58768855e3578a0a8eba49be7")
!134 = !{!135, !137, !138, !139, !140, !141, !142, !143, !144, !145}
!135 = !DIDerivedType(tag: DW_TAG_member, name: "ihl", scope: !132, file: !133, line: 89, baseType: !136, size: 4, flags: DIFlagBitField, extraData: i64 0)
!136 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u8", file: !87, line: 21, baseType: !55)
!137 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !132, file: !133, line: 90, baseType: !136, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!138 = !DIDerivedType(tag: DW_TAG_member, name: "tos", scope: !132, file: !133, line: 97, baseType: !136, size: 8, offset: 8)
!139 = !DIDerivedType(tag: DW_TAG_member, name: "tot_len", scope: !132, file: !133, line: 98, baseType: !116, size: 16, offset: 16)
!140 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !132, file: !133, line: 99, baseType: !116, size: 16, offset: 32)
!141 = !DIDerivedType(tag: DW_TAG_member, name: "frag_off", scope: !132, file: !133, line: 100, baseType: !116, size: 16, offset: 48)
!142 = !DIDerivedType(tag: DW_TAG_member, name: "ttl", scope: !132, file: !133, line: 101, baseType: !136, size: 8, offset: 64)
!143 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !132, file: !133, line: 102, baseType: !136, size: 8, offset: 72)
!144 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !132, file: !133, line: 103, baseType: !129, size: 16, offset: 80)
!145 = !DIDerivedType(tag: DW_TAG_member, scope: !132, file: !133, line: 104, baseType: !146, size: 64, offset: 96)
!146 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !132, file: !133, line: 104, size: 64, elements: !147)
!147 = !{!148, !154}
!148 = !DIDerivedType(tag: DW_TAG_member, scope: !146, file: !133, line: 104, baseType: !149, size: 64)
!149 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !146, file: !133, line: 104, size: 64, elements: !150)
!150 = !{!151, !153}
!151 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !149, file: !133, line: 104, baseType: !152, size: 32)
!152 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be32", file: !117, line: 27, baseType: !86)
!153 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !149, file: !133, line: 104, baseType: !152, size: 32, offset: 32)
!154 = !DIDerivedType(tag: DW_TAG_member, name: "addrs", scope: !146, file: !133, line: 104, baseType: !155, size: 64)
!155 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !146, file: !133, line: 104, size: 64, elements: !156)
!156 = !{!157, !158}
!157 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !155, file: !133, line: 104, baseType: !152, size: 32)
!158 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !155, file: !133, line: 104, baseType: !152, size: 32, offset: 32)
!159 = !DILocalVariable(name: "payload_buffer", scope: !78, file: !3, line: 101, type: !160)
!160 = !DICompositeType(tag: DW_TAG_array_type, baseType: !55, size: 2048, elements: !161)
!161 = !{!162}
!162 = !DISubrange(count: 256)
!163 = !DILocalVariable(name: "header", scope: !78, file: !3, line: 105, type: !56)
!164 = !DILocalVariable(name: "connection_id_length", scope: !165, file: !3, line: 110, type: !81)
!165 = distinct !DILexicalBlock(scope: !166, file: !3, line: 106, column: 32)
!166 = distinct !DILexicalBlock(scope: !78, file: !3, line: 106, column: 9)
!167 = !DILocalVariable(name: "shl", scope: !168, file: !3, line: 116, type: !81)
!168 = distinct !DILexicalBlock(scope: !166, file: !3, line: 114, column: 12)
!169 = !DILocalVariable(name: "packet_number_length", scope: !168, file: !3, line: 124, type: !81)
!170 = !DILocalVariable(name: "packet_number", scope: !168, file: !3, line: 128, type: !81)
!171 = !DILocalVariable(name: "pnoffset", scope: !168, file: !3, line: 131, type: !55)
!172 = !DICompositeType(tag: DW_TAG_array_type, baseType: !173, size: 208, elements: !175)
!173 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !174)
!174 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!175 = !{!176}
!176 = !DISubrange(count: 26)
!177 = !DIGlobalVariableExpression(var: !178, expr: !DIExpression())
!178 = distinct !DIGlobalVariable(name: "bpf_trace_printk", scope: !2, file: !69, line: 177, type: !179, isLocal: true, isDefinition: true)
!179 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !180)
!180 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !181, size: 64)
!181 = !DISubroutineType(types: !182)
!182 = !{!53, !183, !86, null}
!183 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !173, size: 64)
!184 = !DIGlobalVariableExpression(var: !185, expr: !DIExpression())
!185 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 42, type: !186, isLocal: true, isDefinition: true)
!186 = !DICompositeType(tag: DW_TAG_array_type, baseType: !173, size: 328, elements: !187)
!187 = !{!188}
!188 = !DISubrange(count: 41)
!189 = !DIGlobalVariableExpression(var: !190, expr: !DIExpression())
!190 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 47, type: !172, isLocal: true, isDefinition: true)
!191 = !DIGlobalVariableExpression(var: !192, expr: !DIExpression())
!192 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 99, type: !193, isLocal: true, isDefinition: true)
!193 = !DICompositeType(tag: DW_TAG_array_type, baseType: !173, size: 424, elements: !194)
!194 = !{!195}
!195 = !DISubrange(count: 53)
!196 = !DIGlobalVariableExpression(var: !197, expr: !DIExpression())
!197 = distinct !DIGlobalVariable(name: "bpf_probe_read_kernel", scope: !2, file: !69, line: 2807, type: !198, isLocal: true, isDefinition: true)
!198 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !199)
!199 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !200, size: 64)
!200 = !DISubroutineType(types: !201)
!201 = !{!53, !52, !86, !74}
!202 = !DIGlobalVariableExpression(var: !203, expr: !DIExpression())
!203 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 107, type: !204, isLocal: true, isDefinition: true)
!204 = !DICompositeType(tag: DW_TAG_array_type, baseType: !173, size: 216, elements: !205)
!205 = !{!206}
!206 = !DISubrange(count: 27)
!207 = !DIGlobalVariableExpression(var: !208, expr: !DIExpression())
!208 = distinct !DIGlobalVariable(name: "bpf_map_update_elem", scope: !2, file: !69, line: 78, type: !209, isLocal: true, isDefinition: true)
!209 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !210)
!210 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !211, size: 64)
!211 = !DISubroutineType(types: !212)
!212 = !{!53, !52, !74, !74, !213}
!213 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !87, line: 31, baseType: !214)
!214 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!215 = !DIGlobalVariableExpression(var: !216, expr: !DIExpression())
!216 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 115, type: !217, isLocal: true, isDefinition: true)
!217 = !DICompositeType(tag: DW_TAG_array_type, baseType: !173, size: 224, elements: !218)
!218 = !{!219}
!219 = !DISubrange(count: 28)
!220 = !DIGlobalVariableExpression(var: !221, expr: !DIExpression())
!221 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 119, type: !222, isLocal: true, isDefinition: true)
!222 = !DICompositeType(tag: DW_TAG_array_type, baseType: !173, size: 368, elements: !223)
!223 = !{!224}
!224 = !DISubrange(count: 46)
!225 = !DIGlobalVariableExpression(var: !226, expr: !DIExpression())
!226 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 125, type: !227, isLocal: true, isDefinition: true)
!227 = !DICompositeType(tag: DW_TAG_array_type, baseType: !173, size: 320, elements: !228)
!228 = !{!229}
!229 = !DISubrange(count: 40)
!230 = !DIGlobalVariableExpression(var: !231, expr: !DIExpression())
!231 = distinct !DIGlobalVariable(name: "____fmt", scope: !78, file: !3, line: 143, type: !232, isLocal: true, isDefinition: true)
!232 = !DICompositeType(tag: DW_TAG_array_type, baseType: !173, size: 680, elements: !233)
!233 = !{!234}
!234 = !DISubrange(count: 85)
!235 = !DIGlobalVariableExpression(var: !236, expr: !DIExpression())
!236 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 150, type: !237, isLocal: false, isDefinition: true)
!237 = !DICompositeType(tag: DW_TAG_array_type, baseType: !174, size: 32, elements: !238)
!238 = !{!239}
!239 = !DISubrange(count: 4)
!240 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 23, size: 256, elements: !241)
!241 = !{!242, !247, !249, !250}
!242 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !240, file: !3, line: 24, baseType: !243, size: 64)
!243 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !244, size: 64)
!244 = !DICompositeType(tag: DW_TAG_array_type, baseType: !81, size: 64, elements: !245)
!245 = !{!246}
!246 = !DISubrange(count: 2)
!247 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !240, file: !3, line: 25, baseType: !248, size: 64, offset: 64)
!248 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !81, size: 64)
!249 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !240, file: !3, line: 26, baseType: !97, size: 64, offset: 128)
!250 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !240, file: !3, line: 27, baseType: !251, size: 64, offset: 192)
!251 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !252, size: 64)
!252 = !DICompositeType(tag: DW_TAG_array_type, baseType: !81, size: 32, elements: !253)
!253 = !{!254}
!254 = !DISubrange(count: 1)
!255 = !{i32 7, !"Dwarf Version", i32 5}
!256 = !{i32 2, !"Debug Info Version", i32 3}
!257 = !{i32 1, !"wchar_size", i32 4}
!258 = !{i32 7, !"frame-pointer", i32 2}
!259 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!260 = !DILocation(line: 0, scope: !78)
!261 = !DILocation(line: 36, column: 5, scope: !78)
!262 = !DILocation(line: 36, column: 9, scope: !78)
!263 = !{!264, !264, i64 0}
!264 = !{!"int", !265, i64 0}
!265 = !{!"omnipotent char", !266, i64 0}
!266 = !{!"Simple C/C++ TBAA"}
!267 = !DILocation(line: 37, column: 37, scope: !78)
!268 = !DILocation(line: 38, column: 10, scope: !269)
!269 = distinct !DILexicalBlock(scope: !78, file: !3, line: 38, column: 9)
!270 = !DILocation(line: 38, column: 9, scope: !78)
!271 = !DILocation(line: 39, column: 9, scope: !272)
!272 = distinct !DILexicalBlock(scope: !273, file: !3, line: 39, column: 9)
!273 = distinct !DILexicalBlock(scope: !269, file: !3, line: 38, column: 22)
!274 = !DILocation(line: 40, column: 9, scope: !273)
!275 = !DILocation(line: 42, column: 9, scope: !276)
!276 = distinct !DILexicalBlock(scope: !277, file: !3, line: 42, column: 9)
!277 = distinct !DILexicalBlock(scope: !269, file: !3, line: 41, column: 12)
!278 = !{!279, !264, i64 0}
!279 = !{!"meta_struc", !264, i64 0}
!280 = !DILocation(line: 45, column: 30, scope: !78)
!281 = !DILocation(line: 47, column: 5, scope: !282)
!282 = distinct !DILexicalBlock(scope: !78, file: !3, line: 47, column: 5)
!283 = !DILocation(line: 50, column: 41, scope: !78)
!284 = !{!285, !264, i64 4}
!285 = !{!"xdp_md", !264, i64 0, !264, i64 4, !264, i64 8, !264, i64 12, !264, i64 16, !264, i64 20}
!286 = !DILocation(line: 50, column: 30, scope: !78)
!287 = !DILocation(line: 50, column: 22, scope: !78)
!288 = !DILocation(line: 51, column: 37, scope: !78)
!289 = !{!285, !264, i64 0}
!290 = !DILocation(line: 51, column: 26, scope: !78)
!291 = !DILocation(line: 51, column: 18, scope: !78)
!292 = !DILocation(line: 60, column: 21, scope: !293)
!293 = distinct !DILexicalBlock(scope: !78, file: !3, line: 60, column: 9)
!294 = !DILocation(line: 60, column: 36, scope: !293)
!295 = !DILocation(line: 60, column: 9, scope: !78)
!296 = !DILocation(line: 67, column: 20, scope: !297)
!297 = distinct !DILexicalBlock(scope: !78, file: !3, line: 67, column: 9)
!298 = !DILocation(line: 67, column: 34, scope: !297)
!299 = !DILocation(line: 67, column: 9, scope: !78)
!300 = !DILocation(line: 73, column: 13, scope: !301)
!301 = distinct !DILexicalBlock(scope: !78, file: !3, line: 73, column: 9)
!302 = !{!303, !265, i64 9}
!303 = !{!"iphdr", !265, i64 0, !265, i64 0, !265, i64 1, !304, i64 2, !304, i64 4, !304, i64 6, !265, i64 8, !265, i64 9, !304, i64 10, !265, i64 12}
!304 = !{!"short", !265, i64 0}
!305 = !DILocation(line: 73, column: 22, scope: !301)
!306 = !DILocation(line: 73, column: 9, scope: !78)
!307 = !DILocation(line: 80, column: 21, scope: !308)
!308 = distinct !DILexicalBlock(scope: !78, file: !3, line: 80, column: 9)
!309 = !DILocation(line: 80, column: 36, scope: !308)
!310 = !DILocation(line: 80, column: 9, scope: !78)
!311 = !DILocation(line: 86, column: 14, scope: !312)
!312 = distinct !DILexicalBlock(scope: !78, file: !3, line: 86, column: 9)
!313 = !{!314, !304, i64 2}
!314 = !{!"udphdr", !304, i64 0, !304, i64 2, !304, i64 4, !304, i64 6}
!315 = !DILocation(line: 86, column: 19, scope: !312)
!316 = !DILocation(line: 86, column: 39, scope: !312)
!317 = !DILocation(line: 86, column: 47, scope: !312)
!318 = !{!314, !304, i64 0}
!319 = !DILocation(line: 86, column: 54, scope: !312)
!320 = !DILocation(line: 86, column: 9, scope: !78)
!321 = !DILocation(line: 93, column: 20, scope: !78)
!322 = !{!314, !304, i64 4}
!323 = !DILocation(line: 93, column: 36, scope: !78)
!324 = !DILocation(line: 94, column: 25, scope: !325)
!325 = distinct !DILexicalBlock(scope: !78, file: !3, line: 94, column: 9)
!326 = !DILocation(line: 94, column: 40, scope: !325)
!327 = !DILocation(line: 94, column: 9, scope: !78)
!328 = !DILocation(line: 99, column: 5, scope: !329)
!329 = distinct !DILexicalBlock(scope: !78, file: !3, line: 99, column: 5)
!330 = !DILocation(line: 101, column: 5, scope: !78)
!331 = !DILocation(line: 101, column: 19, scope: !78)
!332 = !DILocation(line: 102, column: 5, scope: !78)
!333 = !DILocation(line: 106, column: 17, scope: !166)
!334 = !{!335, !265, i64 0}
!335 = !{!"quic_header_wrapper", !265, i64 0}
!336 = !DILocation(line: 106, column: 25, scope: !166)
!337 = !DILocation(line: 106, column: 9, scope: !78)
!338 = !DILocation(line: 107, column: 9, scope: !339)
!339 = distinct !DILexicalBlock(scope: !165, file: !3, line: 107, column: 9)
!340 = !DILocation(line: 110, column: 9, scope: !165)
!341 = !DILocation(line: 110, column: 36, scope: !165)
!342 = !{!265, !265, i64 0}
!343 = !DILocation(line: 0, scope: !165)
!344 = !DILocation(line: 110, column: 13, scope: !165)
!345 = !DILocation(line: 112, column: 9, scope: !165)
!346 = !DILocation(line: 114, column: 5, scope: !166)
!347 = !DILocation(line: 114, column: 5, scope: !165)
!348 = !DILocation(line: 115, column: 9, scope: !349)
!349 = distinct !DILexicalBlock(scope: !168, file: !3, line: 115, column: 9)
!350 = !DILocation(line: 0, scope: !168)
!351 = !DILocation(line: 118, column: 20, scope: !352)
!352 = distinct !DILexicalBlock(scope: !168, file: !3, line: 118, column: 13)
!353 = !DILocation(line: 118, column: 13, scope: !168)
!354 = !DILocation(line: 119, column: 13, scope: !355)
!355 = distinct !DILexicalBlock(scope: !356, file: !3, line: 119, column: 13)
!356 = distinct !DILexicalBlock(scope: !352, file: !3, line: 118, column: 26)
!357 = !DILocation(line: 120, column: 13, scope: !356)
!358 = !DILocation(line: 124, column: 44, scope: !168)
!359 = !DILocation(line: 124, column: 52, scope: !168)
!360 = !DILocation(line: 125, column: 9, scope: !361)
!361 = distinct !DILexicalBlock(scope: !168, file: !3, line: 125, column: 9)
!362 = !DILocation(line: 131, column: 34, scope: !168)
!363 = !DILocation(line: 133, column: 13, scope: !168)
!364 = !DILocation(line: 134, column: 29, scope: !365)
!365 = distinct !DILexicalBlock(scope: !366, file: !3, line: 133, column: 40)
!366 = distinct !DILexicalBlock(scope: !168, file: !3, line: 133, column: 13)
!367 = !DILocation(line: 135, column: 9, scope: !365)
!368 = !DILocation(line: 136, column: 29, scope: !369)
!369 = distinct !DILexicalBlock(scope: !370, file: !3, line: 135, column: 47)
!370 = distinct !DILexicalBlock(scope: !366, file: !3, line: 135, column: 20)
!371 = !DILocation(line: 136, column: 54, scope: !369)
!372 = !DILocation(line: 136, column: 84, scope: !369)
!373 = !DILocation(line: 136, column: 61, scope: !369)
!374 = !DILocation(line: 136, column: 59, scope: !369)
!375 = !DILocation(line: 137, column: 9, scope: !369)
!376 = !DILocation(line: 138, column: 29, scope: !377)
!377 = distinct !DILexicalBlock(scope: !378, file: !3, line: 137, column: 47)
!378 = distinct !DILexicalBlock(scope: !370, file: !3, line: 137, column: 20)
!379 = !DILocation(line: 138, column: 54, scope: !377)
!380 = !DILocation(line: 138, column: 77, scope: !377)
!381 = !DILocation(line: 138, column: 85, scope: !377)
!382 = !DILocation(line: 138, column: 62, scope: !377)
!383 = !DILocation(line: 138, column: 89, scope: !377)
!384 = !DILocation(line: 138, column: 60, scope: !377)
!385 = !DILocation(line: 138, column: 119, scope: !377)
!386 = !DILocation(line: 138, column: 96, scope: !377)
!387 = !DILocation(line: 138, column: 94, scope: !377)
!388 = !DILocation(line: 139, column: 9, scope: !377)
!389 = !DILocation(line: 143, column: 9, scope: !390)
!390 = distinct !DILexicalBlock(scope: !168, file: !3, line: 143, column: 9)
!391 = !DILocation(line: 145, column: 5, scope: !166)
!392 = !DILocation(line: 148, column: 1, scope: !78)
