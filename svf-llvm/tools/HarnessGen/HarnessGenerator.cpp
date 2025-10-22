//===- HarnessGenerator.cpp -- Fuzzing Harness Generator Implementation-------//

#include "HarnessGenerator.h"
#include "Util/SVFUtil.h"
#include "SVF-LLVM/BasicTypes.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/LLVMModule.h"
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Support/raw_ostream.h>
#include <iostream>
#include <llvm/IR/Verifier.h>

using namespace SVF;
using namespace SVFUtil;

/// Main entry point
bool HarnessGenerator::generateHarness()
{
    outs() << "========== Harness Generator ==========\n";
    outs() << "Target function: " << targetFuncName << "\n";
    outs() << "Enclosing function: " << enclosingFuncName << "\n\n";

    // Phase 1: Locate call site
    if (!locateTargetCallSite())
    {
        errs() << "ERROR: Could not locate call to '" << targetFuncName
               << "' in function '" << enclosingFuncName << "'\n";
        return false;
    }

    // Phase 2: Backward slice
    computeBackwardSlice();

    // Phase 3: Forward slice
    computeForwardSlice();

    // Phase 4: Combine slices
    combineSlices();

    // Print statistics
    printSliceStats();

    return true;
}

/// Phase 1: Locate call site of target function in enclosing function
bool HarnessGenerator::locateTargetCallSite()
{
    // Step 1: Find the target and enclosing functions
    targetFunc = findFunction(targetFuncName);
    if (!targetFunc)
    {
        errs() << "ERROR: Target function '" << targetFuncName << "' not found\n";
        return false;
    }

    enclosingFunc = findFunction(enclosingFuncName);
    if (!enclosingFunc)
    {
        errs() << "ERROR: Enclosing function '" << enclosingFuncName << "' not found\n";
        return false;
    }

    outs() << "Found target function: " << targetFunc->getName() << "\n";
    outs() << "Found enclosing function: " << enclosingFunc->getName() << "\n";

    // Step 2: Get ICFG and iterate through all call sites
    ICFG* icfg = pag->getICFG();
    CallGraph* cg = pta->getCallGraph();

    for (const auto& nodePair : *icfg)
    {
        const ICFGNode* node = nodePair.second;

        // Only check nodes in enclosing function
        if (node->getFun() != enclosingFunc)
            continue;

        // Check if this is a call node
        if (const CallICFGNode* callNode = SVFUtil::dyn_cast<CallICFGNode>(node))
        {
            // Get all possible callees for this call site
            CallGraph::FunctionSet callees;
            cg->getCallees(callNode, callees);

            // Check if target function is in the callee set
            for (const FunObjVar* callee : callees)
            {
                if (callee == targetFunc)
                {
                    // Found it!
                    targetCallSite = callNode;
                    outs() << "Found call site at: " << callNode->toString() << "\n";
                    return true;
                }
            }
        }
    }

    errs() << "ERROR: Could not find call to '" << targetFuncName
           << "' in function '" << enclosingFuncName << "'\n";
    return false;
}

/// Helper: Find SVF function by name
const FunObjVar* HarnessGenerator::findFunction(const std::string& funcName) const
{
    // Try to find in all SVF values (PAG nodes)
    for (auto it = pag->begin(); it != pag->end(); ++it)
    {
        const PAGNode* node = it->second;
        if (const FunObjVar* func = SVFUtil::dyn_cast<FunObjVar>(node))
        {
            if (func->getName() == funcName)
            {
                return func;
            }
        }
    }
    return nullptr;
}

/// Helper: Check if a node belongs to the enclosing function
bool HarnessGenerator::isInEnclosingFunction(const SVFGNode* node) const
{
    const ICFGNode* icfgNode = node->getICFGNode();
    if (!icfgNode)
        return false;

    return icfgNode->getFun() == enclosingFunc;
}

/// Phase 2: Compute backward slice from call arguments
void HarnessGenerator::computeBackwardSlice()
{
    backwardSlice.clear();
    SVFGWorkList worklist;
    SVFGNodeSet visited;

    // Step 1: Initialize worklist with actual parameter nodes
    // Get all arguments passed to the target function at the call site

    // Get the actual parameters from PAG
    if (pag->hasCallSiteArgsMap(targetCallSite))
    {
        const SVFIR::SVFVarList& argList = pag->getCallSiteArgsList(targetCallSite);

        outs() << "Analyzing " << argList.size() << " arguments to '"
               << targetFuncName << "'\n";

        for (const PAGNode* argNode : argList)
        {
            // Get corresponding SVFG node
            if (svfg->hasActualParmVFGNode(argNode, targetCallSite))
            {
                const ActualParmVFGNode* apNode =
                    svfg->getActualParmVFGNode(argNode, targetCallSite);
                worklist.push(apNode);
                outs() << "  Starting backward slice from argument: "
                       << apNode->toString() << "\n";
            }
        }
    }

    // Step 2: Backward traversal using worklist algorithm
    while (!worklist.empty())
    {
        const SVFGNode* node = worklist.pop();

        // Skip if already visited
        if (visited.find(node) != visited.end())
            continue;

        visited.insert(node);

        // Check if node is in enclosing function (boundary check)
        if (!isInEnclosingFunction(node))
        {
            // Reached boundary - this is an input to the slice
            // If it's a FormalParmVFGNode, it's a parameter of enclosing function
            if (SVFUtil::isa<FormalParmVFGNode>(node))
            {
                outs() << "  [Boundary] Found input parameter: " << node->toString() << "\n";
            }
            continue;
        }

        // Add to backward slice
        backwardSlice.insert(node);

        // Traverse backward through incoming edges
        for (auto it = node->InEdgeBegin(); it != node->InEdgeEnd(); ++it)
        {
            const VFGEdge* edge = *it;
            const SVFGNode* predNode = edge->getSrcNode();

            // Only follow intra-procedural edges (stay within enclosing function)
            if (edge->isDirectVFGEdge())
            {
                // Direct def-use edge within the function
                worklist.push(predNode);
            }
            else if (edge->isIndirectVFGEdge())
            {
                // Memory dependency edge (load/store)
                // Only follow if it's within the enclosing function
                if (isInEnclosingFunction(predNode))
                {
                    worklist.push(predNode);
                }
            }
            // Skip inter-procedural edges (CallIndirectVFGEdge, RetIndirectVFGEdge)
            // unless they are to callees within the enclosing function
        }
    }

    outs() << "Backward slice contains " << backwardSlice.size() << " nodes\n";

    // Print detailed slice information
    outs() << "\n--- Backward Slice Details ---\n";
    for (const SVFGNode* node : backwardSlice)
    {
        const ICFGNode* icfgNode = node->getICFGNode();
        if (icfgNode)
        {
            outs() << "  [" << node->getNodeKind() << "] ";

            // Print different types of nodes
            if (const StmtVFGNode* stmtNode = SVFUtil::dyn_cast<StmtVFGNode>(node))
            {
                outs() << stmtNode->toString() << "\n";
            }
            else if (SVFUtil::isa<PHISVFGNode>(node))
            {
                outs() << "PHI node: " << node->toString() << "\n";
            }
            else if (SVFUtil::isa<FormalParmVFGNode>(node))
            {
                outs() << "Formal param: " << node->toString() << "\n";
            }
            else
            {
                outs() << node->toString() << "\n";
            }
        }
    }
    outs() << "--- End Backward Slice ---\n\n";
}

/// Phase 3: Compute forward slice from return value
void HarnessGenerator::computeForwardSlice()
{
    forwardSlice.clear();
    SVFGWorkList worklist;
    SVFGNodeSet visited;

    // Step 1: Get the return value PAGNode from the call site
    // Get the RetICFGNode associated with this CallICFGNode
    const RetICFGNode* retICFGNode = targetCallSite->getRetICFGNode();

    if (!retICFGNode || !pag->callsiteHasRet(retICFGNode))
    {
        outs() << "Target function call has no return value (void)\n";
        return;
    }

    // Get the return value PAGNode
    const SVFVar* retPAGNode = pag->getCallSiteRet(retICFGNode);

    // Step 2: Get the ActualRetVFGNode from SVFG
    if (!svfg->hasActualRetVFGNode(retPAGNode))
    {
        outs() << "No ActualRetVFGNode in SVFG for return value\n";
        return;
    }

    outs() << "Analyzing return value from '" << targetFuncName << "'\n";

    // Get the ActualRetVFGNode
    const ActualRetVFGNode* arNode = svfg->getActualRetVFGNode(retPAGNode);
    worklist.push(arNode);
    outs() << "  Starting forward slice from return value: "
           << arNode->toString() << "\n";

    // Step 3: Forward traversal using worklist algorithm
    while (!worklist.empty())
    {
        const SVFGNode* node = worklist.pop();

        // Skip if already visited
        if (visited.find(node) != visited.end())
            continue;

        visited.insert(node);

        // Check if node is in enclosing function (boundary check)
        if (!isInEnclosingFunction(node))
        {
            // Reached boundary - this is an output from the slice
            // If it's a FormalRetVFGNode, it's the return of enclosing function
            if (SVFUtil::isa<FormalRetVFGNode>(node))
            {
                outs() << "  [Boundary] Reaches return of enclosing function: "
                       << node->toString() << "\n";
            }
            continue;
        }

        // Add to forward slice
        forwardSlice.insert(node);

        // Traverse forward through outgoing edges
        for (auto it = node->OutEdgeBegin(); it != node->OutEdgeEnd(); ++it)
        {
            const VFGEdge* edge = *it;
            const SVFGNode* succNode = edge->getDstNode();

            // Only follow intra-procedural edges (stay within enclosing function)
            if (edge->isDirectVFGEdge())
            {
                // Direct use-def edge within the function
                worklist.push(succNode);
            }
            else if (edge->isIndirectVFGEdge())
            {
                // Memory dependency edge (load/store)
                // Only follow if it's within the enclosing function
                if (isInEnclosingFunction(succNode))
                {
                    worklist.push(succNode);
                }
            }
            // Skip inter-procedural edges unless within enclosing function
        }
    }

    outs() << "Forward slice contains " << forwardSlice.size() << " nodes\n";
}

/// Phase 4: Combine slices
void HarnessGenerator::combineSlices()
{
    combinedSlice = backwardSlice;
    for (const SVFGNode* node : forwardSlice)
    {
        combinedSlice.insert(node);
    }
}

/// Helper: Print slice statistics
void HarnessGenerator::printSliceStats() const
{
    outs() << "\n========== Slice Statistics ==========\n";
    outs() << "Backward slice nodes: " << backwardSlice.size() << "\n";
    outs() << "Forward slice nodes: " << forwardSlice.size() << "\n";
    outs() << "Combined slice nodes: " << combinedSlice.size() << "\n";
    outs() << "======================================\n";
}

/// Phase 5: Generate output
void HarnessGenerator::generateOutput(const std::string& outputFile)
{
    // Step 1: Write slice information to output file
    std::error_code EC;
    llvm::raw_fd_ostream outStream(outputFile, EC);
    if (EC)
    {
        errs() << "ERROR: Could not open output file: " << EC.message() << "\n";
        return;
    }

    // Write backward slice
    outStream << "; ========== Backward Slice (Computes arguments to " << targetFuncName << ") ==========\n";
    for (const SVFGNode* node : backwardSlice)
    {
        outStream << ";   [Node " << node->getId() << "] " << node->toString() << "\n";
    }

    // Write forward slice
    outStream << "\n; ========== Forward Slice (Uses return value from " << targetFuncName << ") ==========\n";
    for (const SVFGNode* node : forwardSlice)
    {
        outStream << ";   [Node " << node->getId() << "] " << node->toString() << "\n";
    }

    outStream.close();

    // Step 2: Generate actual sliced LLVM IR function
    outs() << "\nGenerating sliced LLVM IR function...\n";

    // Get the LLVM module
    llvm::Module* module = LLVMModuleSet::getLLVMModuleSet()->getMainLLVMModule();
    if (!module)
    {
        errs() << "ERROR: Could not get LLVM module\n";
        return;
    }

    llvm::Function* slicedFunc = generateSlicedFunction(module);
    if (slicedFunc)
    {
        std::string slicedFuncName = slicedFunc->getName().str();
        outs() << "Sliced function '" << slicedFuncName << "' created\n";

        // Note: CloneFunction already added the function to the module, so no push_back needed

        // Strip function-level debug info
        slicedFunc->setSubprogram(nullptr);

        // Remove all debug intrinsic calls and strip metadata from instructions
        /*
        std::vector<llvm::Instruction*> toRemove;
        for (llvm::BasicBlock& BB : *slicedFunc)
        {
            for (llvm::Instruction& I : BB)
            {
                // If it's a debug intrinsic (like llvm.dbg.declare), mark for removal
                if (llvm::CallInst* CI = llvm::dyn_cast<llvm::CallInst>(&I))
                {
                    if (llvm::Function* callee = CI->getCalledFunction())
                    {
                        if (callee->getName().startswith("llvm.dbg."))
                        {
                            toRemove.push_back(&I);
                            continue;
                        }
                    }
                }

                // Strip all metadata from regular instructions
                llvm::SmallVector<std::pair<unsigned, llvm::MDNode*>, 4> MDs;
                I.getAllMetadata(MDs);
                for (auto& MD : MDs)
                {
                    I.setMetadata(MD.first, nullptr);
                }
            }
        }
        */
        /*
        // Remove debug intrinsics
        for (llvm::Instruction* I : toRemove)
        {
            I->eraseFromParent();
        }

        outs() << "Stripped debug info: removed " << toRemove.size()
               << " debug intrinsics from sliced function\n";

        // The sliced function is ALREADY in the module (CloneFunction added it automatically)
        outs() << "Sliced function already in module alongside original\n";
        */

        // Write the modified module to file
        std::string irOutputFile = outputFile + ".sliced.ll";
        std::error_code EC2;
        llvm::raw_fd_ostream irStream(irOutputFile, EC2);
        if (!EC2)
        {
            outs() << "Writing module with both original and sliced functions to " << irOutputFile << "...\n";
            module->print(irStream, nullptr);
            irStream.close();
            outs() << "Module written to: " << irOutputFile << "\n";
        }
    }
}

/// Helper: Generate sliced LLVM IR function
llvm::Function* HarnessGenerator::generateSlicedFunction(llvm::Module* module)
{
    // Get the original LLVM function by name from the module
    llvm::Function* originalFunc = module->getFunction(enclosingFuncName);

    // Create new function name: caller_callee_slice_cloned
    std::string slicedFuncName = enclosingFuncName + "_" + targetFuncName + "_slice_cloned_SVF";

    outs() << "Creating sliced function: " << slicedFuncName << "\n";
    outs() << "Original function: " << originalFunc->getName().str() << " with "
           << originalFunc->getInstructionCount() << " instructions\n";

    // Clone the function
    llvm::ValueToValueMapTy VMap;
    // clonedFunc has been added to the original function's module by `CloneFunction`
    llvm::Function* clonedFunc = llvm::CloneFunction(originalFunc, VMap);
    clonedFunc->setName(slicedFuncName);

    // Collect instructions from the slice
    std::set<const llvm::Instruction*> sliceInsts;
    for (const SVFGNode* node : combinedSlice)
    {
        const ICFGNode* icfgNode = node->getICFGNode();
        if (!icfgNode) continue;

        // Try to get the SVF value and convert to LLVM instruction
        const SVFVar* svfVar = node->getValue();
        if (svfVar)
        {
            const llvm::Value* llvmVal = LLVMModuleSet::getLLVMModuleSet()->getLLVMValue(svfVar);
            if (const llvm::Instruction* inst = llvm::dyn_cast_or_null<llvm::Instruction>(llvmVal))
            {
                sliceInsts.insert(inst);
            }
        }
    }

    outs() << "Slice contains " << sliceInsts.size() << " LLVM instructions to keep\n";

    // Map original instructions to cloned instructions
    std::set<llvm::Instruction*> clonedSliceInsts;
    for (const llvm::Instruction* origInst : sliceInsts)
    {
        if (VMap.count(origInst))
        {
            if (llvm::Instruction* clonedInst = llvm::dyn_cast<llvm::Instruction>(VMap[origInst]))
            {
                clonedSliceInsts.insert(clonedInst);
            }
        }
    }

    // Compute a def-use closure over the cloned slice, so all operand producers
    // required by kept instructions are preserved.
    std::set<llvm::Instruction*> keepSet = clonedSliceInsts;
    std::vector<llvm::Instruction*> workQ(keepSet.begin(), keepSet.end());
    while (!workQ.empty()) {
        llvm::Instruction* I = workQ.back(); workQ.pop_back();
        for (llvm::Value* Op : I->operands()) {
            if (auto *OpI = llvm::dyn_cast<llvm::Instruction>(Op)) {
                //if (isa<llvm::DbgInfoIntrinsic>(OpI)) continue;
                if (OpI->getFunction() == clonedFunc && !keepSet.count(OpI)) {
                    keepSet.insert(OpI);
                    workQ.push_back(OpI);
                }
            }
        }
    }

    // Ensure terminators of blocks that contain kept instructions are kept
    for (llvm::Instruction* I : keepSet) {
        llvm::BasicBlock* BB = I->getParent();
        if (BB && BB->getTerminator()) keepSet.insert(BB->getTerminator());
    }

    // Remove all other non-terminator instructions. Replace remaining uses
    // with undef to keep IR valid.
    std::vector<llvm::Instruction*> toErase;
    for (llvm::BasicBlock &BB : *clonedFunc) {
        for (llvm::Instruction &I : llvm::make_early_inc_range(BB)) {
            if (keepSet.count(&I)) continue;
            if (I.isTerminator()) continue; // keep all terminators for validity
            if (!I.getType()->isVoidTy() && !I.use_empty()) {
                I.replaceAllUsesWith(llvm::UndefValue::get(I.getType()));
            }
            toErase.push_back(&I);
        }
    } 
    for (llvm::Instruction* I : toErase) I->eraseFromParent();

    llvm::removeUnreachableBlocks(*clonedFunc);
    bool bad = llvm::verifyFunction(*clonedFunc, &llvm::errs());
    if (bad) {
        errs() << "ERROR: Generated sliced function is invalid!\n";
        return nullptr;
    }

    outs() << "Reduced cloned function to " << keepSet.size() << " instructions\n";


    return clonedFunc;
}
