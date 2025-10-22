//===- FunctionLevelSlicer.h -- Function-Level LLVM IR Slicer -------------===//
//
// This class extracts a minimal function-level slice from an LLVM module
// based on reachability from a target function.
//
// Properties:
//   (a) S ⊆ P - slice is smaller than or equal to the program
//   (b) F ⊂ S - target function F is in the slice
//   (c) If F1 ⊂ S and F1 calls F2 (direct call), then F2 ⊂ S
//
//===----------------------------------------------------------------------===//

#ifndef FUNCTIONLEVELSLICER_H
#define FUNCTIONLEVELSLICER_H

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <set>
#include <map>
#include <string>
#include <vector>

namespace llvm {
    class Module;
    class Function;
    class GlobalVariable;
}

class FunctionLevelSlicer
{
public:
    FunctionLevelSlicer();
    ~FunctionLevelSlicer();

    /// Load LLVM module from bitcode file
    bool loadModule(const std::string& bitcodeFile);

    /// Set the target function (F) that encloses the warning
    bool setTargetFunction(const std::string& funcName);

    /// Extract the minimal function-level slice
    /// Returns a new module containing only functions reachable from target
    llvm::Module* extractSlice();

    /// Write the sliced module to a bitcode file
    bool writeSlicedModule(const std::string& outputFile);

    /// Get statistics
    size_t getOriginalFunctionCount() const;
    size_t getSlicedFunctionCount() const;
    double getReductionPercentage() const;
    void printStatistics() const;

    /// Get the sliced module (nullptr if not yet extracted)
    llvm::Module* getSlicedModule() const { return slicedModule; }

private:
    // Core data structures
    llvm::Module* originalModule;
    llvm::Module* slicedModule;
    llvm::LLVMContext context;

    std::set<llvm::Function*> targetFunctions;
    std::set<llvm::GlobalVariable*> globalSlice;

    // Persistent mapping from original -> sliced Values used across cloning
    llvm::ValueToValueMapTy valueMap;

    // Helper methods for slice extraction
    void collectReachableFunctions();
    void collectUsedGlobals();
    void buildSlicedModule();

    // Module cloning helpers
    void cloneGlobalVariables();
    void cloneFunctionDeclarations();
    void cloneFunctionBodies();
    void updateFunctionReferences();
    void removeProgramEntryDecl();
    // Stubs are not emitted: non-target functions remain declarations only

    // Utility methods
    llvm::Function* findFunctionByName(const std::string& name);
    void findDirectCallees(llvm::Function* func, std::vector<llvm::Function*>& callees);
    bool isIntrinsicOrBuiltin(llvm::Function* func);

    // Statistics
    size_t originalFuncCount;
};

#endif // FUNCTIONLEVELSLICER_H
