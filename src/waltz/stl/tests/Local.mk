ifdef FD_HAS_HOSTED
STL_TEST_LIBS:=fd_stl fd_util fd_ballet

# fd_stl unit tests
$(call make-unit-test,test_stl_all,      test_stl_all,      $(STL_TEST_LIBS))
$(call run-unit-test,test_stl_all)

endif
