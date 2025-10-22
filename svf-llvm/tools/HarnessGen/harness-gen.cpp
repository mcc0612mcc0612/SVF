//===- harness-gen.cpp -- Fuzzing Harness Generator Tool------------------//
//
// Driver program for the fuzzing harness generator
//
//===-----------------------------------------------------------------------===//

#include "HarnessGenerator.h"
#include "FunctionLevelSlicer.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Graphs/SVFG.h"
#include "WPA/Steensgaard.h"
#include "Util/CommandLine.h"
#include "Util/Options.h"

using namespace llvm;
using namespace std;
using namespace SVF;

// Command line options
static llvm::cl::opt<std::string> TargetFunc("target",
        llvm::cl::desc("Target function to fuzz (function 'a')"),
        llvm::cl::value_desc("function-name"));

static llvm::cl::opt<std::string> EnclosingFunc("enclosing",
        llvm::cl::desc("Enclosing function containing the call (function 'b')"),
        llvm::cl::value_desc("function-name"));

static llvm::cl::opt<std::string> OutputFile("output",
        llvm::cl::desc("Output file for generated harness"),
        llvm::cl::init("harness.ll"),
        llvm::cl::value_desc("filename"));

int main(int argc, char** argv)
{
    if (argc < 4) {
        errs() << "Usage: " << argv[0] << " <target-func> <enclosing-func> <input.bc>\n";
        errs() << "Example: " << argv[0] << " add compute test_example.ll\n";
        return 1;
    }

    std::string targetName = argv[1];
    std::string enclosingName = argv[2];
    std::string inputBitcode = argv[3];

    // Extract minimal slice: keep enclosing function body, stub all others
    // This reduces SVFIR building time and memory usage

    outs() << "\n========== PHASE 1: Function-Level Slicing ==========\n";

    FunctionLevelSlicer slicer;

    // Load the original module
    if (!slicer.loadModule(inputBitcode))
    {
        errs() << "Failed to load module: " << inputBitcode << "\n";
        return 1;
    }

    // Set the enclosing function as the target (F that encloses the warning)
    if (!slicer.setTargetFunction(enclosingName))
    {
        errs() << "Failed to set target function: " << enclosingName << "\n";
        return 1;
    }

    // Extract the slice (enclosing function body + stubs for all others)
    llvm::Module* slicedModule = slicer.extractSlice();
    if (!slicedModule)
    {
        errs() << "Failed to extract function-level slice\n";
        return 1;
    }


    outs() << "========== PHASE 2: Building SVFIR on Sliced Module ==========\n";

    // Build SVF module
    LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(*slicedModule);

    // Build SVFIR (PAG)
    SVFIRBuilder builder;
    SVFIR* pag = builder.build();

    // Run pointer analysis (Andersen's)
    outs() << "Running Andersen pointer analysis...\n";
    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);

    SVFGBuilder svfBuilder;
    SVFG* svfg = svfBuilder.buildFullSVFG(ander);

    outs() << "========== PHASE 3: Harness Generation ==========\n";

    // Create harness generator
    HarnessGenerator generator(pag, svfg, ander);
    generator.setTargetFunction(targetName);
    generator.setEnclosingFunction(enclosingName);

    // Generate harness
    if (generator.generateHarness())
    {
        outs() << "\nHarness generation successful!\n";
        generator.generateOutput("harness.ll");
    }
    else
    {
        errs() << "\nHarness generation failed!\n";
        return 1;
    }

    // Cleanup
    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();
    LLVMModuleSet::releaseLLVMModuleSet();
    llvm::llvm_shutdown();

    return 0;
}
