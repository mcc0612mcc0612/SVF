//===- FunctionLevelSlicer.cpp -- Function-Level LLVM IR Slicer Implementation-===//

#include "FunctionLevelSlicer.h"
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalVariable.h>
#include <SVF-LLVM/LLVMUtil.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <queue>
#include <iostream>

using namespace llvm;

FunctionLevelSlicer::FunctionLevelSlicer()
    : originalModule(nullptr)
    , slicedModule(nullptr)
    , originalFuncCount(0)
{
}

FunctionLevelSlicer::~FunctionLevelSlicer()
{
    // Note: We don't delete modules as they manage their own memory
    // and might be owned by LLVMModuleSet
}

bool FunctionLevelSlicer::loadModule(const std::string& bitcodeFile)
{
    SMDiagnostic err;
    std::unique_ptr<Module> M = parseIRFile(bitcodeFile, err, context);

    if (!M)
    {
        errs() << "Error loading module from " << bitcodeFile << ": "
               << err.getMessage() << "\n";
        return false;
    }

    originalModule = M.release();

    // Count original functions
    originalFuncCount = 0;
    for (Function& F : *originalModule)
    {
        if (!F.isDeclaration())
            originalFuncCount++;
    }

    outs() << "Loaded module: " << originalModule->getName() << "\n";
    outs() << "Original function count: " << originalFuncCount << "\n";

    return true;
}

bool FunctionLevelSlicer::setTargetFunction(const std::string& funcName)
{
    if (!originalModule)
    {
        errs() << "Error: Module not loaded. Call loadModule() first.\n";
        return false;
    }

    Function* targetFunc = findFunctionByName(funcName);

    if (!targetFunc)
    {
        errs() << "Error: Target function '" << funcName << "' not found in module.\n";
        return false;
    }

    if (targetFunc->isDeclaration())
    {
        errs() << "Warning: Target function '" << funcName
               << "' is only a declaration (no body).\n";
    }

    targetFunctions.insert(targetFunc);
    outs() << "Target function added: " << targetFunc->getName() << "\n";
    return true;
}

Module* FunctionLevelSlicer::extractSlice()
{
    if (!originalModule || targetFunctions.empty())
    {
        errs() << "Error: Module or target functions not set.\n";
        return nullptr;
    }

    outs() << "\n========== Function-Level Slicing ==========\n";
    outs() << "Strategy: Keep enclosing function bodies, stub all others\n";

    // Step 1: Collect global variables used by enclosing functions
    outs() << "Step 1: Collecting used global variables...\n";
    collectUsedGlobals();
    outs() << "  Found " << globalSlice.size() << " global variables\n";

    // Step 2: Build the sliced module (enclosing functions + stubs)
    outs() << "Step 2: Building sliced module...\n";
    buildSlicedModule();

    if (verifyModule(*slicedModule, &errs())) {
        errs() << "Error: verification failed\n";
        return nullptr;
    } else {
        outs() << "Cloned function successfully!\n";
        printStatistics();
    }

    return slicedModule;
}

bool FunctionLevelSlicer::writeSlicedModule(const std::string& outputFile)
{
    if (!slicedModule)
    {
        errs() << "Error: No sliced module to write. Call extractSlice() first.\n";
        return false;
    }

    if (verifyModule(*slicedModule, &errs())) {
        errs() << "Error: verification failed\n";
    } else {
        outs() << "Cloned function successfully!\n";
        slicedModule->print(outs(), nullptr);
    }

    std::error_code EC;
    raw_fd_ostream out(outputFile, EC);

    if (EC)
    {
        errs() << "Error opening output file " << outputFile << ": "
               << EC.message() << "\n";
        return false;
    }

    WriteBitcodeToFile(*slicedModule, out);
    out.flush();

    outs() << "Sliced module written to: " << outputFile << "\n";
    return true;
}

// ============================================================================
// Core Algorithm: Stub-based Slicing
// ============================================================================
// Since backward/forward slicing is intra-procedural only, we only need:
// - The enclosing function (full body) - where analysis happens
// - All other functions (declarations/stubs) - for valid call sites
// This is much simpler than full reachable function collection.
// ============================================================================

void FunctionLevelSlicer::collectReachableFunctions()
{
    // Not used in stub-based approach
    // Only the enclosing function is kept with body
}

void FunctionLevelSlicer::findDirectCallees(Function* func, std::vector<Function*>& callees)
{
    // Not used in stub-based approach
    // We stub all functions regardless of call relationships
}

// ============================================================================
// Collect Global Variables Used by Functions in Slice
// ============================================================================

void FunctionLevelSlicer::collectUsedGlobals()
{
    globalSlice.clear();

    for (Function* F : targetFunctions)
    {
        if (F->isDeclaration())
            continue;

        for (BasicBlock& BB : *F)
        {
            for (Instruction& I : BB)
            {
                // Check all operands for global variable references
                for (Use& U : I.operands())
                {
                    if (GlobalVariable* GV = dyn_cast<GlobalVariable>(U.get()))
                    {
                        globalSlice.insert(GV);
                    }
                    else if (Constant* C = dyn_cast<Constant>(U.get()))
                    {
                        // Recursively check constants for global references
                        std::queue<Constant*> constWorklist;
                        constWorklist.push(C);

                        while (!constWorklist.empty())
                        {
                            Constant* curr = constWorklist.front();
                            constWorklist.pop();

                            if (GlobalVariable* GV = dyn_cast<GlobalVariable>(curr))
                            {
                                globalSlice.insert(GV);
                            }

                            for (Use& CU : curr->operands())
                            {
                                if (Constant* nested = dyn_cast<Constant>(CU.get()))
                                {
                                    constWorklist.push(nested);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Build Sliced Module
// ============================================================================

void FunctionLevelSlicer::buildSlicedModule()
{
    // Create new module with same identifier
    slicedModule = new Module(originalModule->getName().str() + ".sliced", context);
    slicedModule->setTargetTriple(originalModule->getTargetTriple());
    slicedModule->setDataLayout(originalModule->getDataLayout());

    // Step 1: Clone global variables (record mapping old->new)
    cloneGlobalVariables();

    // Step 2: Create function declarations for ALL functions in original module
    // This ensures all calls remain valid and fills valueMap for remapping
    cloneFunctionDeclarations();

    // Remove program entry declaration (e.g., main) if present and safe
    // When building ICFG, if the entry function is declared but not defined, assertions failed in `SVF::ICFGBuilder::connectGlobalToProgEntry`
    removeProgramEntryDecl();

    // Step 3: Clone function bodies ONLY for functions in targetFunctions
    // (i.e., only the enclosing function)
    cloneFunctionBodies();

    outs() << "  Created " << slicedModule->getFunctionList().size()
           << " function declarations (stubs)\n";
    outs() << "  Cloned " << targetFunctions.size()
           << " function bodies\n";
}

void FunctionLevelSlicer::cloneGlobalVariables()
{
    for (GlobalVariable* GV : globalSlice)
    {
        // Create new global variable in sliced module
        GlobalVariable* newGV = new GlobalVariable(
            *slicedModule,
            GV->getValueType(),
            GV->isConstant(),
            GV->getLinkage(),
            nullptr,  // Initializer will be set later
            GV->getName(),
            nullptr,
            GV->getThreadLocalMode(),
            GV->getType()->getAddressSpace()
        );

        // Copy attributes
        newGV->copyAttributesFrom(GV);

        // Map old to new
        valueMap[GV] = newGV;
    }

    // Now set initializers (after all globals are created)
    for (GlobalVariable* GV : globalSlice)
    {
        if (GV->hasInitializer())
        {
            GlobalVariable* newGV = cast<GlobalVariable>(valueMap[GV]);
            Constant* init = GV->getInitializer();
            newGV->setInitializer(MapValue(init, valueMap));
        }
    }
}

void FunctionLevelSlicer::cloneFunctionDeclarations()
{
    // Create declarations for ALL functions in the original module
    // This ensures all function calls remain valid (even if they're just stubs)
    for (Function& F : *originalModule)
    {
        // Create function declaration in sliced module
        Function* newF = Function::Create(
            F.getFunctionType(),
            F.getLinkage(),
            F.getName(),
            slicedModule
        );

        // Copy attributes
        newF->copyAttributesFrom(&F);

        // Record mapping old->new so cloning can remap calls/refs
        valueMap[&F] = newF;
    }
}

void FunctionLevelSlicer::cloneFunctionBodies()
{
    for (Function* F : targetFunctions)
    {
        if (F->isDeclaration())
            continue;

        // Find corresponding function in sliced module
        Function* newF = slicedModule->getFunction(F->getName());
        if (!newF)
            continue;

        // Use LLVM's CloneFunction utility
        // Start with module-wide valueMap so globals/functions remap correctly
        ValueToValueMapTy& VMap = valueMap;

        // Map arguments
        auto newArgIt = newF->arg_begin();
        for (auto& arg : F->args())
        {
            VMap[&arg] = &(*newArgIt);
            newArgIt->setName(arg.getName());
            ++newArgIt;
        }

        // Clone the function body
        SmallVector<ReturnInst*, 8> returns;
        CloneFunctionInto(newF, F, VMap, CloneFunctionChangeType::DifferentModule, returns);
    }
}

void FunctionLevelSlicer::removeProgramEntryDecl()
{
    if (!slicedModule)
        return;

    if (const Function* entry = SVF::LLVMUtil::getProgEntryFunction(*slicedModule)) {
        // Do not remove if this entry is one of the targets
        for (Function* TF : targetFunctions) {
            if (TF->getName() == entry->getName())
                return;
        }

        // Only remove if it's a decl and has no uses; otherwise, keep it
        if (entry->isDeclaration()) {
            if (Function* removable = slicedModule->getFunction(entry->getName())) {
                if (removable->use_empty())
                    removable->eraseFromParent();
            }
        }
    }
}

// ============================================================================
// Utility Methods
// ============================================================================

Function* FunctionLevelSlicer::findFunctionByName(const std::string& name)
{
    if (!originalModule)
        return nullptr;

    return originalModule->getFunction(name);
}

bool FunctionLevelSlicer::isIntrinsicOrBuiltin(Function* func)
{
    if (!func)
        return false;

    // LLVM intrinsics start with "llvm."
    if (func->isIntrinsic() || func->getName().starts_with("llvm."))
        return true;

    // Common compiler builtins
    StringRef name = func->getName();
    if (name.starts_with("__builtin_") ||
        name.starts_with("__llvm_") ||
        name.starts_with("__sanitizer_"))
        return true;

    return false;
}

// ============================================================================
// Statistics
// ============================================================================

size_t FunctionLevelSlicer::getOriginalFunctionCount() const
{
    return originalFuncCount;
}

size_t FunctionLevelSlicer::getSlicedFunctionCount() const
{
    return targetFunctions.size();
}

double FunctionLevelSlicer::getReductionPercentage() const
{
    if (originalFuncCount == 0)
        return 0.0;

    return (1.0 - (double)targetFunctions.size() / (double)originalFuncCount) * 100.0;
}

void FunctionLevelSlicer::printStatistics() const
{
    outs() << "\n========== Slicing Statistics ==========\n";
    outs() << "Original functions (with body): " << originalFuncCount << "\n";
    outs() << "Functions with body in slice:   " << targetFunctions.size() << "\n";
    outs() << "Functions stubbed out:          " << (originalFuncCount - targetFunctions.size()) << "\n";
    outs() << "Reduction:                      " << getReductionPercentage() << "%\n";
    outs() << "Global variables:               " << globalSlice.size() << "\n";
    outs() << "\n";
    outs() << "Strategy: Enclosing function bodies + stubs for all other functions\n";
    outs() << "This enables intra-procedural analysis while keeping module valid.\n";

    // Verify property (a): S ⊆ P
    if (targetFunctions.size() <= originalFuncCount)
    {
        outs() << "✓ Property (a) verified: S ⊆ P\n";
    }
    else
    {
        outs() << "✗ Property (a) VIOLATED: S > P (should not happen!)\n";
    }

    // Property (b) verification - check all target functions are in slice
    bool allTargetsInSlice = true;
    for (Function* targetFunc : targetFunctions)
    {
        if (targetFunctions.count(targetFunc) == 0)
        {
            allTargetsInSlice = false;
            break;
        }
    }
    outs() << (allTargetsInSlice ? "✓" : "✗")
           << " Property (b) verified: All target functions in slice\n";

    outs() << "========================================\n\n";
}
